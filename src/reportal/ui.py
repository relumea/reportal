"""SPA, static asset and generated report routes for reportal.

``/`` serves the built React app (``web/`` built by Vite into ``assets/dist``)
and ``/static/<path>`` serves the hashed assets next to it.  The build output
is generated, not committed, so a checkout without a build answers 503
``ui-not-built`` instead of a broken shell.  ``/reports/<id>/`` and
``/reports/<id>/<path>`` serve the HTML site ``rebrew report`` writes into the
workspace's ``reports/<id>`` tree, so the site a report run generated is
browsable without leaving the portal.  Every request is resolved under its own
root and refused when it escapes it, so a traversal cannot read elsewhere.

Hashed JS/CSS are answered compressed when the client asks for it: a sibling
``.br`` (brotli) or ``.gz`` written at build time (``scripts/precompress_spa.py``)
is preferred in that order, otherwise the response is gzip-compressed at the
request-time level.  Already-compressed formats and tiny bodies are left alone.
"""

from __future__ import annotations

import gzip
import hashlib
import mimetypes
import shutil
import subprocess
from email.utils import formatdate, parsedate
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Request
from starlette.responses import FileResponse, Response
from starlette.staticfiles import NotModifiedResponse

from reportal import landing
from reportal._paths import SPA_INDEX, SPA_NOT_BUILT_DETAIL, reports_dir, spa_dist_dir
from reportal.server import (
    ACCEPT_ENCODING,
    GZIP_LEVEL,
    accepts_br,
    accepts_gzip,
    json_error,
)

router = APIRouter()

# Entry page of a generated report site; a request for the report root serves
# this instead of a directory listing.
REPORT_INDEX = "index.html"

# Entry page of the built SPA, and the hint a 503 carries when it is missing.
# Owned by :mod:`reportal._paths` so doctor preflight can read them without
# importing this route module.
APP_INDEX = SPA_INDEX
UI_NOT_BUILT_DETAIL = SPA_NOT_BUILT_DETAIL

# Where Vite writes the hashed bundles, relative to the dist directory.  A file
# under it carries its content hash in its name, so a browser may keep it
# forever: a deploy writes a new name rather than new bytes behind the old one.
ASSET_DIRECTORY = "assets"
ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable"

# Everything else the SPA serves (the entry page and the favicon) can change
# under its own name, so a browser revalidates it and a deploy is picked up on
# the next load rather than a year later.
SHELL_CACHE_CONTROL = "no-cache"

# Textual assets worth compressing.  Images, fonts and archives are already
# compressed; compressing them again wastes CPU and can grow the body.
COMPRESSIBLE_SUFFIXES = frozenset(
    {".css", ".html", ".js", ".json", ".map", ".mjs", ".svg", ".txt", ".xml"}
)

# Below this, the gzip framing usually costs more than it saves.
MIN_COMPRESS_BYTES = 256

# Cap the in-process gzip cache so a long-lived server does not retain every
# historical hashed bundle after many deploys without a restart.
_GZIP_CACHE_SIZE = 64


def dist_dir() -> Path:
    """Directory holding the built SPA (Vite output, generated and gitignored)."""
    return spa_dist_dir()


def _report_root(binary_id: int) -> Path:
    """Return the report site root of *binary_id*, or raise a JSON 404.

    A binary whose report was never generated has no directory, so the caller
    gets an actionable ``no-report`` error instead of a directory listing or a
    generic 404 page.
    """
    root = reports_dir(binary_id)
    if not root.is_dir():
        raise json_error(
            404,
            error="no-report",
            detail=f"no report site for binary {binary_id}; run 'reportal report {binary_id}'",
        )
    return root


def _media_type(path: Path) -> str:
    """MIME type for *path*, with sensible defaults Vite's suffixes need."""
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed is not None:
        return guessed
    suffix = path.suffix.lower()
    if suffix == ".js" or suffix == ".mjs":
        return "text/javascript"
    if suffix == ".css":
        return "text/css"
    if suffix == ".svg":
        return "image/svg+xml"
    return "application/octet-stream"


def _resolve_under(root: Path, relative: str) -> Path:
    """Return the file at *relative* under *root*, or raise a JSON 404.

    The candidate is resolved before it is checked, so a ``..`` segment, an
    absolute path or a symlink that leaves the tree is a not-found rather than
    a read outside it.
    """
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate == root or root not in candidate.parents or not candidate.is_file():
        raise json_error(404, error="not found", detail=f"no such file: {relative}")
    return candidate


@lru_cache(maxsize=_GZIP_CACHE_SIZE)
def _gzip_cached(path_str: str, mtime_ns: int, size: int) -> bytes:
    """Gzip *path_str* at the request-time level; keyed so a rebuild invalidates."""
    del mtime_ns, size  # part of the cache key only
    return gzip.compress(Path(path_str).read_bytes(), GZIP_LEVEL)


def _precompressed_sibling(path: Path, suffix: str) -> Path | None:
    """Return a fresh precompressed sibling, or None when missing or stale."""
    sibling = Path(f"{path}{suffix}")
    try:
        if (
            sibling.is_file()
            and sibling.stat().st_mtime_ns >= path.stat().st_mtime_ns
            and sibling.stat().st_size > 0
        ):
            return sibling
    except OSError:
        return None
    return None


def _compressed_response(path: Path, *, cache_control: str) -> Response | None:
    """A compressed response for *path*, or None when the client or body cannot use it.

    Prefers a sibling ``.br`` written by ``scripts/precompress_spa.py`` when the
    client accepts brotli, then a sibling ``.gz`` (build-time effort 9).  Without
    either, compresses in process at :data:`GZIP_LEVEL` and caches the result
    keyed by path identity and mtime.  A precompressed sibling is served even
    when the source is small: the build step already decided it was worth keeping.
    """
    if path.suffix.lower() not in COMPRESSIBLE_SUFFIXES:
        return None
    accept = ACCEPT_ENCODING.get()
    headers_base = {"Cache-Control": cache_control, "Vary": "Accept-Encoding"}
    media_type = _media_type(path)
    if accepts_br(accept):
        br_path = _precompressed_sibling(path, ".br")
        if br_path is not None:
            return FileResponse(
                br_path,
                media_type=media_type,
                headers={**headers_base, "Content-Encoding": "br"},
            )
    if not accepts_gzip(accept):
        return None
    gz_path = _precompressed_sibling(path, ".gz")
    if gz_path is not None:
        return FileResponse(
            gz_path,
            media_type=media_type,
            headers={**headers_base, "Content-Encoding": "gzip"},
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < MIN_COMPRESS_BYTES:
        return None
    try:
        body = _gzip_cached(str(path), path.stat().st_mtime_ns, size)
    except OSError:
        return None
    return Response(
        content=body,
        media_type=media_type,
        headers={
            **headers_base,
            "Content-Encoding": "gzip",
            "ETag": f'"{hashlib.sha256(body).hexdigest()}"',
            "Last-Modified": formatdate(path.stat().st_mtime, usegmt=True),
        },
    )


def _revalidate(response: Response, request: Request) -> Response:
    if isinstance(response, FileResponse):
        response.set_stat_headers(Path(response.path).stat())
    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None:
        etag = response.headers["etag"]
        matched = if_none_match.strip() == "*" or etag in (
            tag.strip().removeprefix("W/") for tag in if_none_match.split(",")
        )
    else:
        modified_since = parsedate(request.headers.get("if-modified-since", ""))
        last_modified = parsedate(response.headers.get("last-modified", ""))
        matched = (
            modified_since is not None
            and last_modified is not None
            and modified_since >= last_modified
        )
    return NotModifiedResponse(response.headers) if matched else response


def _file_under(
    root: Path, relative: str, request: Request, *, cache_control: str | None = None
) -> Response:
    """Serve *relative* under *root*, compressed when that pays off."""
    candidate = _resolve_under(root, relative)
    control = cache_control if cache_control is not None else SHELL_CACHE_CONTROL
    response = _compressed_response(candidate, cache_control=control)
    if response is None:
        response = FileResponse(candidate)
        response.headers["Cache-Control"] = control
        if candidate.suffix.lower() in COMPRESSIBLE_SUFFIXES:
            response.headers["Vary"] = "Accept-Encoding"
    return _revalidate(response, request)


@router.get("/")
def index(request: Request) -> Response:
    """Serve the built SPA shell, or a 503 when the frontend was never built.

    The entry page names the deploy's own asset hashes, so it is answered
    `no-cache`: a browser revalidates it (a 304 while the build is unchanged)
    and picks up a new build on the next load.
    """
    root = dist_dir()
    if not (root / APP_INDEX).is_file():
        raise json_error(503, error="ui-not-built", detail=UI_NOT_BUILT_DETAIL)
    return _file_under(root, APP_INDEX, request, cache_control=SHELL_CACHE_CONTROL)


@lru_cache(maxsize=8)
def _pricing_encodings(raw: bytes) -> tuple[bytes, bytes | None]:
    """Gzip (and brotli when the CLI is present) for a pricing body, once per body.

    The page is derived from code and only changes on deploy, so maximum gzip
    effort is paid once per distinct markup rather than on every request.
    """
    gz = gzip.compress(raw, compresslevel=9)
    br: bytes | None = None
    binary = shutil.which("brotli")
    if binary is not None:
        try:
            completed = subprocess.run(
                [binary, "-q", "11", "-c"],
                input=raw,
                capture_output=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            completed = None
        if completed is not None and completed.stdout and len(completed.stdout) < len(raw):
            br = completed.stdout
    return gz, br


@router.get("/pricing")
def pricing(request: Request) -> Response:
    """The public marketing and pricing page, rendered from the plan catalog.

    Served whether or not the SPA has been built: it is the page a visitor who
    has never signed in reads, so it must not depend on a frontend build step.
    Bodies are content-addressed (``ETag``) so a repeat load after ``max-age``
    can be answered ``304`` instead of re-sending the markup.
    """
    raw = landing.render().encode("utf-8")
    accept = ACCEPT_ENCODING.get()
    etag_plain = hashlib.sha256(raw).hexdigest()
    body = raw
    encoding: str | None = None
    if len(raw) >= MIN_COMPRESS_BYTES:
        gz, br = _pricing_encodings(raw)
        if br is not None and accepts_br(accept):
            body, encoding = br, "br"
        elif accepts_gzip(accept):
            body, encoding = gz, "gzip"
    etag = f'"{etag_plain}-{encoding or "identity"}"'
    headers = {
        "Cache-Control": landing.CACHE_CONTROL,
        "Vary": "Accept-Encoding",
        "ETag": etag,
    }
    if encoding is not None:
        headers["Content-Encoding"] = encoding
    response = Response(
        content=body,
        media_type="text/html; charset=utf-8",
        headers=headers,
    )
    return _revalidate(response, request)


@router.get("/static/{path:path}")
def asset(path: str, request: Request) -> Response:
    """Serve one built SPA asset, cached by content address when it has one.

    Vite writes each bundle under a name carrying its content hash, so the
    bundles are answered `immutable` and a repeat load makes no request for
    them; a file without a hash (the favicon) is answered `no-cache` instead.
    """
    hashed = Path(path).parent.as_posix() == ASSET_DIRECTORY
    control = ASSET_CACHE_CONTROL if hashed else SHELL_CACHE_CONTROL
    return _file_under(dist_dir(), path, request, cache_control=control)


@router.get("/reports/{binary_id}/")
def report_index(binary_id: int, request: Request) -> Response:
    """Serve the entry page of a binary's generated report site."""
    return _file_under(_report_root(binary_id), REPORT_INDEX, request)


@router.get("/reports/{binary_id}/{path:path}")
def report_file(binary_id: int, path: str, request: Request) -> Response:
    """Serve one file of a binary's generated report site."""
    return _file_under(_report_root(binary_id), path, request)

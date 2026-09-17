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
import mimetypes
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter
from starlette.responses import FileResponse, Response

from reportal import landing
from reportal._paths import reports_dir
from reportal.server import (
    _ACCEPT_ENCODING,
    GZIP_LEVEL,
    _accepts_br,
    _accepts_gzip,
    json_error,
)

router = APIRouter()

# Entry page of a generated report site; a request for the report root serves
# this instead of a directory listing.
REPORT_INDEX = "index.html"

# Entry page of the built SPA, and the hint a 503 carries when it is missing.
APP_INDEX = "index.html"
UI_NOT_BUILT_DETAIL = "run 'bun install && bun run build' in web/"

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
    return Path(__file__).resolve().parent / "assets" / "dist"


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
    accept = _ACCEPT_ENCODING.get()
    headers_base = {"Cache-Control": cache_control, "Vary": "Accept-Encoding"}
    media_type = _media_type(path)
    if _accepts_br(accept):
        br_path = _precompressed_sibling(path, ".br")
        if br_path is not None:
            return FileResponse(
                br_path,
                media_type=media_type,
                headers={**headers_base, "Content-Encoding": "br"},
            )
    if not _accepts_gzip(accept):
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
        headers={**headers_base, "Content-Encoding": "gzip"},
    )


def _file_under(root: Path, relative: str, *, cache_control: str | None = None) -> Response:
    """Serve *relative* under *root*, compressed when that pays off."""
    candidate = _resolve_under(root, relative)
    control = cache_control if cache_control is not None else SHELL_CACHE_CONTROL
    compressed = _compressed_response(candidate, cache_control=control)
    if compressed is not None:
        return compressed
    response = FileResponse(candidate)
    response.headers["Cache-Control"] = control
    if candidate.suffix.lower() in COMPRESSIBLE_SUFFIXES:
        response.headers["Vary"] = "Accept-Encoding"
    return response


@router.get("/")
def index() -> Response:
    """Serve the built SPA shell, or a 503 when the frontend was never built.

    The entry page names the deploy's own asset hashes, so it is answered
    `no-cache`: a browser revalidates it (a 304 while the build is unchanged)
    and picks up a new build on the next load.
    """
    root = dist_dir()
    if not (root / APP_INDEX).is_file():
        raise json_error(503, error="ui-not-built", detail=UI_NOT_BUILT_DETAIL)
    return _file_under(root, APP_INDEX, cache_control=SHELL_CACHE_CONTROL)


@router.get("/pricing")
def pricing() -> Response:
    """The public marketing and pricing page, rendered from the plan catalog.

    Served whether or not the SPA has been built: it is the page a visitor who
    has never signed in reads, so it must not depend on a frontend build step.
    """
    body = landing.render().encode("utf-8")
    headers = {"Cache-Control": landing.CACHE_CONTROL, "Vary": "Accept-Encoding"}
    if len(body) >= MIN_COMPRESS_BYTES and _accepts_gzip(_ACCEPT_ENCODING.get()):
        body = gzip.compress(body, GZIP_LEVEL)
        headers["Content-Encoding"] = "gzip"
    return Response(
        content=body,
        media_type="text/html; charset=utf-8",
        headers=headers,
    )


@router.get("/static/{path:path}")
def asset(path: str) -> Response:
    """Serve one built SPA asset, cached by content address when it has one.

    Vite writes each bundle under a name carrying its content hash, so the
    bundles are answered `immutable` and a repeat load makes no request for
    them; a file without a hash (the favicon) is answered `no-cache` instead.
    """
    hashed = Path(path).parent.as_posix() == ASSET_DIRECTORY
    control = ASSET_CACHE_CONTROL if hashed else SHELL_CACHE_CONTROL
    return _file_under(dist_dir(), path, cache_control=control)


@router.get("/reports/{binary_id}/")
def report_index(binary_id: int) -> Response:
    """Serve the entry page of a binary's generated report site."""
    return _file_under(_report_root(binary_id), REPORT_INDEX)


@router.get("/reports/{binary_id}/{path:path}")
def report_file(binary_id: int, path: str) -> Response:
    """Serve one file of a binary's generated report site."""
    return _file_under(_report_root(binary_id), path)

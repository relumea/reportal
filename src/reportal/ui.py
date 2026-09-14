"""SPA, static asset and generated report routes for reportal.

``/`` serves the built React app (``web/`` built by Vite into ``assets/dist``)
and ``/static/<path>`` serves the hashed assets next to it.  The build output
is generated, not committed, so a checkout without a build answers 503
``ui-not-built`` instead of a broken shell.  ``/reports/<id>/`` and
``/reports/<id>/<path>`` serve the HTML site ``rebrew report`` writes into the
workspace's ``reports/<id>`` tree, so the site a report run generated is
browsable without leaving the portal.  Every request is resolved under its own
root and refused when it escapes it, so a traversal cannot read elsewhere.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from starlette.responses import FileResponse, Response

from reportal._paths import reports_dir
from reportal.server import json_error

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


def _file_under(root: Path, relative: str) -> Response:
    """Serve *relative* under *root*, or a JSON 404.

    The candidate is resolved before it is checked, so a ``..`` segment, an
    absolute path or a symlink that leaves the tree is a not-found rather than
    a read outside it.
    """
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate == root or root not in candidate.parents or not candidate.is_file():
        raise json_error(404, error="not found", detail=f"no such file: {relative}")
    return FileResponse(candidate)


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
    return FileResponse(root / APP_INDEX, headers={"Cache-Control": SHELL_CACHE_CONTROL})


@router.get("/static/{path:path}")
def asset(path: str) -> Response:
    """Serve one built SPA asset, cached by content address when it has one.

    Vite writes each bundle under a name carrying its content hash, so the
    bundles are answered `immutable` and a repeat load makes no request for
    them; a file without a hash (the favicon) is answered `no-cache` instead.
    """
    response = _file_under(dist_dir(), path)
    hashed = Path(path).parent.as_posix() == ASSET_DIRECTORY
    response.headers["Cache-Control"] = ASSET_CACHE_CONTROL if hashed else SHELL_CACHE_CONTROL
    return response


@router.get("/reports/{binary_id}/")
def report_index(binary_id: int) -> Response:
    """Serve the entry page of a binary's generated report site."""
    return _file_under(_report_root(binary_id), REPORT_INDEX)


@router.get("/reports/{binary_id}/{path:path}")
def report_file(binary_id: int, path: str) -> Response:
    """Serve one file of a binary's generated report site."""
    return _file_under(_report_root(binary_id), path)

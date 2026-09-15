"""The API reference stays a provenance of the router: docs/API.md must carry a
table row for every route the FastAPI app answers.

The CLI reference already has this promise (`tests/test_cli_docs.py` walks the
Typer app against docs/CLI.md); this is the same shape for the HTTP surface.
It walks the live router tables (api.router plus ui.router: the composed app
keeps included routers lazy, so the app table alone misses every API route)
and fails the gate for a route with no row, or no same-method family row,
which is how the `remediation/yara` row covers `remediation/<fmt>`.
"""

import re
from pathlib import Path

from reportal import api, ui

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DOCS = REPO_ROOT / "docs" / "API.md"


def router_routes() -> set[tuple[str, str]]:
    """(method, path) pairs from the live router tables.

    The two routers directly: the composed app keeps included routers lazy
    (FastAPI renders them onto the table at serve time), so the app table
    alone misses every API route.
    """
    routes: set[tuple[str, str]] = set()
    for router in (api.router, ui.router):
        for route in router.routes:
            methods = sorted(getattr(route, "methods", None) or ())
            path = str(getattr(route, "path", ""))
            if not methods or not path.startswith("/api/"):
                continue
            for method in methods:
                if method in {"HEAD", "OPTIONS"}:
                    continue
                routes.add((method, path))
    return routes


def norm(path: str) -> str:
    """One spelling for a parameter segment, whatever its name.

    Both sides normalize: the router writes `{binary_id}`, the reference
    mostly writes `<id>` but keeps a descriptive name (`<user_id>`,
    `<history_id>`) where the row needs it.
    """
    path = re.sub(r"\{[^}/]+\}", "<id>", path)
    return re.sub(r"<[^>]+>", "<id>", path)


def family(path: str) -> str:
    """The path with its last segment dropped: the family a row may name."""
    return "/".join(path.split("/")[:-1]) + "/"


def doc_rows(doc: str) -> dict[str, set[str]]:
    """Table paths per method from the reference's own rows."""
    rows: dict[str, set[str]] = {}
    for line in doc.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not cells[0].startswith("`/api"):
            continue
        method = cells[1].split()[0] if len(cells) > 1 and cells[1] else ""
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        rows.setdefault(method, set()).add(norm(cells[0].strip("`")))
    return rows


def check_paths(routes: set[tuple[str, str]], rows: dict[str, set[str]]) -> list[str]:
    """Routes with no table row of their own and no same-method family row.

    The family fallback exists for one shape only: a route whose last segment
    is a parameter and whose doc names concrete values there (the
    ``remediation/<fmt>`` route beside its ``remediation/yara`` row).  It never
    applies to a concrete route, so removing a real row is always reported.
    """
    problems: list[str] = []
    for method, path in sorted(routes):
        own = norm(path)
        if own in rows.get(method, set()):
            continue
        last = own.split("/")[-1]
        if last == "<id>" and any(
            row.startswith(family(own)) and row != own for row in rows.get(method, set())
        ):
            continue
        problems.append(f"{method} {path}: no row in docs/API.md")
    return problems


def check_docs() -> list[str]:
    """Routes with no table row of their own and no same-method family row."""
    return check_paths(router_routes(), doc_rows(API_DOCS.read_text(encoding="utf-8")))


def test_every_route_has_a_table_row_or_family() -> None:
    problems = check_docs()
    assert problems == [], "\n".join(problems)


def test_an_undocumented_route_is_reported() -> None:
    routes = {("GET", "/api/probe/{thing_id}")}
    rows = {"GET": {"/api/other"}}
    assert check_paths(routes, rows) == ["GET /api/probe/{thing_id}: no row in docs/API.md"]


def test_a_family_row_covers_its_last_segment() -> None:
    routes = {("GET", "/api/things/{fmt}")}
    rows = {"GET": {"/api/things/yara"}}
    assert check_paths(routes, rows) == []

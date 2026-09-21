"""The documentation tree's own gate: links, index, ownership, budgets.

Four promises this file keeps, each one a way docs rot:

- every relative link in the maintained markdown resolves, anchor included;
- every page under ``docs/`` is reachable from the index of its directory (so a
  new page is not invisible to a reader who starts at ``docs/README.md``);
- every module in ``src/reportal`` is owned by exactly one subsystem page's
  ``Sources:`` line, and no page claims a path that is not a module;
- every standing document has a word ceiling in ``docs/doc-budgets.json`` and
  stays under it, so a page cannot grow into a second ARCHITECTURE.md.

The generated catalogs are checked for freshness by
``tests/test_generated_docs.py``; this file only checks the tree they sit in.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"
PACKAGE = REPO_ROOT / "src" / "reportal"
BUDGETS = DOCS / "doc-budgets.json"
GEN_DOCS = REPO_ROOT / "scripts" / "gen_docs.py"

ROOT_PAGES = ("AGENTS.md", "README.md", "CONTRIBUTING.md", "SECURITY.md")

# Standing documents under the budget: the standard, the index, and the two
# authored page trees.  The per-surface references (API.md and its siblings) and
# the backlog are gated by their own tests, not by a word ceiling.
BUDGETED_DIRS = ("subsystems", "cookbook")
BUDGETED_FILES = ("AGENTS.md", "README.md")

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _load_gen_docs() -> Any:
    """The generator module, so this file and it share one ownership parser."""
    spec = importlib.util.spec_from_file_location("gen_docs", GEN_DOCS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def markdown_files() -> list[Path]:
    """Every maintained page: the docs tree plus the root references."""
    found = sorted(DOCS.rglob("*.md"))
    found.extend(REPO_ROOT / name for name in ROOT_PAGES)
    return [path for path in found if path.is_file()]


def prose_lines(path: Path) -> list[str]:
    """A page's lines with fenced code removed, so a template link is not a link."""
    lines: list[str] = []
    fence: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        marker = FENCE_RE.match(line)
        if marker:
            fence = None if fence else marker.group(1)[0] * 3
            continue
        if fence is None:
            lines.append(line)
    return lines


def anchors(path: Path) -> set[str]:
    """Every heading anchor a markdown file offers."""
    found: set[str] = set()
    for line in prose_lines(path):
        heading = HEADING_RE.match(line)
        if heading:
            slug = re.sub(r"[^a-z0-9\s-]", "", heading.group(2).lower()).strip()
            found.add(re.sub(r"\s+", "-", slug))
    return found


def links(path: Path) -> list[str]:
    """Every relative markdown target in a page, anchors included."""
    found: list[str] = []
    for line in prose_lines(path):
        for target in LINK_RE.findall(line):
            if target.startswith(("http://", "https://", "mailto:", "#", "/")):
                continue
            if "<" in target or ">" in target:
                continue
            found.append(target)
    return found


def index_of(page: Path) -> Path:
    """The page that must list *page*.

    A top-level page, and any index, is listed by ``docs/README.md``; a page in
    a subdirectory is listed by that directory's own README.
    """
    if page.parent == DOCS or page.name == "README.md":
        return DOCS / "README.md"
    return page.parent / "README.md"


def test_every_relative_link_resolves() -> None:
    broken: list[str] = []
    for path in markdown_files():
        for target in links(path):
            relative, _, anchor = target.partition("#")
            resolved = path if not relative else (path.parent / relative).resolve()
            if not resolved.exists():
                broken.append(f"{path.relative_to(REPO_ROOT)} -> {target} (no such file)")
                continue
            if anchor and resolved.suffix == ".md" and anchor.lower() not in anchors(resolved):
                broken.append(f"{path.relative_to(REPO_ROOT)} -> {target} (no such heading)")
    assert not broken, "\n".join(broken)


def test_every_page_is_indexed() -> None:
    unindexed: list[str] = []
    for path in sorted(DOCS.rglob("*.md")):
        if path.parent == DOCS and path.name == "README.md":
            continue
        index = index_of(path)
        assert index.is_file(), f"{index.relative_to(REPO_ROOT)} is missing"
        targets = {(index.parent / link.partition("#")[0]).resolve() for link in links(index)}
        if path.resolve() not in targets:
            unindexed.append(f"{path.relative_to(REPO_ROOT)} (from {index.name})")
    assert not unindexed, "\n".join(unindexed)


def test_module_ownership_is_exactly_once() -> None:
    owned = _load_gen_docs().subsystem_sources()
    claimed = [module for modules in owned.values() for module in modules]
    modules = sorted(f"src/reportal/{path.name}" for path in PACKAGE.glob("*.py"))
    duplicates = sorted({module for module in claimed if claimed.count(module) > 1})
    unowned = sorted(set(modules) - set(claimed))
    unknown = sorted(set(claimed) - set(modules))
    assert not duplicates, f"owned by more than one page: {duplicates}"
    assert not unowned, f"owned by no subsystem page: {unowned}"
    assert not unknown, f"claimed but not a module: {unknown}"


def test_subsystem_index_lists_every_page() -> None:
    owned = _load_gen_docs().subsystem_sources()
    index = (DOCS / "subsystems" / "README.md").read_text(encoding="utf-8")
    missing = [f"{page}.md" for page in sorted(owned) if f"({page}.md)" not in index]
    assert not missing, f"not listed in docs/subsystems/README.md: {missing}"


def budgeted_paths() -> set[str]:
    """Repository-relative paths under a word ceiling."""
    paths = {f"docs/{name}" for name in BUDGETED_FILES}
    for directory in BUDGETED_DIRS:
        paths.update(
            str(path.relative_to(REPO_ROOT)) for path in sorted((DOCS / directory).glob("*.md"))
        )
    return paths


def test_budget_manifest_covers_the_standing_documents() -> None:
    manifest = json.loads(BUDGETS.read_text(encoding="utf-8"))
    budgets: dict[str, int] = manifest["budgets"]
    standing = budgeted_paths()
    missing = sorted(standing - set(budgets))
    stale = sorted(set(budgets) - standing)
    assert not missing, f"no ceiling in {BUDGETS.name}: {missing}"
    assert not stale, f"ceiling for a file that is gone: {stale}"
    over = [
        f"{name}: {len((REPO_ROOT / name).read_text(encoding='utf-8').split())} > {budgets[name]}"
        for name in sorted(standing)
        if len((REPO_ROOT / name).read_text(encoding="utf-8").split()) > budgets[name]
    ]
    assert not over, "\n".join(over)


def test_the_authored_tiers_use_no_em_dash() -> None:
    offenders: list[str] = []
    for path in sorted(DOCS.rglob("*.md")):
        relative = path.relative_to(DOCS)
        if relative.parent.name not in BUDGETED_DIRS and path.name not in BUDGETED_FILES:
            continue
        if "\u2014" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"em dash in {offenders}"

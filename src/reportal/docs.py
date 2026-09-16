"""The in-app documentation browser: the shipped markdown as structured blocks.

The same material the repository carries as `docs/*.md` and `CHANGELOG.md` is
served here, so the portal can show its own manual rather than pointing at a
checkout.  The reader does not return HTML: it returns a page's *structure* (a
title, the headings for the on-this-page list and a flat list of blocks) and the
SPA renders it, so no document text is ever injected as markup and there is no
markdown library to carry.

The subset is deliberate and stated rather than guessed at: headings, paragraphs,
fenced code, unordered and ordered lists, block quotes and tables are blocks,
and inline emphasis is left as its literal markdown.  A construct outside the
subset becomes a paragraph, which is readable rather than lost.

Where the documents live is resolved once per request: an explicit
`REPORTAL_DOCS` override, the workspace's own `docs/` directory, the checkout
the package was installed from, or the packaged `manual/` directory the wheel
ships.  A wheel with neither the checkout nor that package-data directory
answers 404 `no-docs` with that reason instead of an empty page.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from reportal import __version__

# The environment override for the documentation directory.
DOCS_ENV = "REPORTAL_DOCS"

# The files the browser serves: the repository's docs directory and the
# changelog beside it.  A page's slug is its filename without its extension.
DOCS_DIRECTORY = "docs"
# Packaged copy under the installed wheel (`scripts/sync_packaged_docs.py`).
PACKAGED_MANUAL = "manual"
CHANGELOG_FILE = "CHANGELOG.md"

# The largest document the reader will parse, so a stray huge file cannot turn a
# page load into a slow parse.
MAX_DOC_BYTES = 512 * 1024

# The knowledge scope the manual is ingested into when a conversation asks about
# reportal itself (TODO entry 16).  The scope has no id of its own, so every
# caller passes the sentinel :data:`SCOPE_ID`.
SCOPE_KIND = "docs"
SCOPE_ID = 0

# The error code the surfaces report when no documentation directory resolves.
ERROR_NO_DOCS = "no-docs"
ERROR_NO_DOC = "no-doc"

# The page order a reader sees: the index first, then the manual in the order a
# person reads it, then the reference material.
PAGE_ORDER: tuple[str, ...] = (
    "README",
    "ARCHITECTURE",
    "API",
    "CLI",
    "SPA",
    "DATA_MODEL",
    "COMPONENTS",
    "THREAT_MODEL",
    "ERRORS",
    "PARITY",
    "TODO",
    "DEPLOY",
    "DR_RUNBOOK",
    "REVENGAI",
)

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^\s*(```+|~~~+)\s*([\w+-]*)\s*$")
_LIST_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
_TABLE_RE = re.compile(r"^\s*\|(.+)\|\s*$")
_TABLE_RULE_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


class DocsError(Exception):
    """Base class for a documentation read that cannot be answered."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class NoDocsError(DocsError, LookupError):
    """No documentation directory resolved; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NO_DOCS, detail)


class UnknownDocError(DocsError, LookupError):
    """No page carries the requested slug; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NO_DOC, detail)


def documents_dir() -> Path | None:
    """The directory the documents are read from, or None when there is none.

    An explicit ``REPORTAL_DOCS`` wins, then the workspace's own ``docs/``
    directory, then the checkout the package was installed from (an editable
    install keeps one), then the packaged ``manual/`` directory the wheel
    ships.  None is the honest answer when none of those resolve, and every
    caller turns it into 404 ``no-docs``.
    """
    override = os.environ.get(DOCS_ENV, "").strip()
    if override:
        candidate = Path(override).expanduser()
        return candidate if candidate.is_dir() else None
    from reportal import _paths

    try:
        workspace = _paths.project_root() / DOCS_DIRECTORY
    except _paths.WorkspaceNotFound:
        workspace = None
    if workspace is not None and workspace.is_dir():
        return workspace
    # <checkout>/src/reportal/docs.py -> <checkout>/docs
    checkout = Path(__file__).resolve().parent.parent.parent / DOCS_DIRECTORY
    if checkout.is_dir():
        return checkout
    packaged = Path(__file__).resolve().parent / PACKAGED_MANUAL
    return packaged if packaged.is_dir() else None


def changelog_path() -> Path | None:
    """The changelog beside the documentation, or None when there is none."""
    directory = documents_dir()
    if directory is None:
        return None
    candidates = [directory.parent / CHANGELOG_FILE, directory / CHANGELOG_FILE]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _slug_of(path: Path) -> str:
    """One file's slug: its stem, lowercased."""
    return path.stem.lower()


def _title_of(text: str, fallback: str) -> str:
    """A document's title: its first level-one heading, else its fallback."""
    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match and len(match.group(1)) == 1:
            return match.group(2).strip()
    return fallback


def pages() -> list[dict[str, Any]]:
    """Every shipped page, in reading order.

    Raises :class:`NoDocsError` when no documentation directory resolves.
    """
    if documents_dir() is None:
        raise NoDocsError(
            f"no documentation directory: set {DOCS_ENV}, run from a workspace with"
            " a docs/ directory, or read the repository"
        )
    listing: list[dict[str, Any]] = []
    for path in _page_files():
        text = _read(path)
        fallback = "Changelog" if path.name == CHANGELOG_FILE else path.stem
        listing.append({"slug": _slug_of(path), "title": _title_of(text, fallback)})
    return listing


def _read(path: Path) -> str:
    """One document's text, bounded; an unreadable file reads as empty."""
    try:
        if path.stat().st_size > MAX_DOC_BYTES:
            return path.read_text(encoding="utf-8", errors="replace")[:MAX_DOC_BYTES]
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _slug_path(slug: str) -> Path:
    """The file one slug names; raises :class:`UnknownDocError` when there is none."""
    resolved = str(slug or "").strip().lower()
    if not resolved or "/" in resolved or "\\" in resolved or resolved.startswith("."):
        raise UnknownDocError(f"{slug!r} is not a documentation page")
    changelog = changelog_path()
    if changelog is not None and resolved == _slug_of(changelog):
        return changelog
    directory = documents_dir()
    if directory is None:
        raise NoDocsError(
            f"no documentation directory: set {DOCS_ENV}, run from a workspace with"
            " a docs/ directory, or read the repository"
        )
    candidate = directory / f"{resolved}.md"
    if candidate.is_file():
        return candidate
    for path in sorted(directory.glob("*.md")):
        if _slug_of(path) == resolved:
            return path
    raise UnknownDocError(f"no documentation page named {slug!r}")


def _anchor(text: str, index: int) -> str:
    """A stable anchor for a heading, unique within the page."""
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    return f"{base}-{index}" if index else base


def blocks(text: str) -> list[dict[str, Any]]:
    """One document's body as a flat list of blocks.

    The subset is: headings, paragraphs, fenced code, lists (ordered or not),
    block quotes and tables.  Anything else becomes a paragraph, so a construct
    the reader does not know is shown rather than dropped.
    """
    result: list[dict[str, Any]] = []
    lines = text.splitlines()
    index = 0
    paragraph: list[str] = []

    def flush() -> None:
        if paragraph:
            joined = "\n".join(paragraph).strip()
            if joined:
                result.append({"kind": "paragraph", "text": joined})
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        fence = _FENCE_RE.match(line)
        if fence:
            flush()
            marker = fence.group(1)[0] * 3
            lang = fence.group(2)
            body: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith(marker):
                body.append(lines[index])
                index += 1
            index += 1
            result.append({"kind": "code", "lang": lang, "text": "\n".join(body)})
            continue
        heading = _HEADING_RE.match(line)
        if heading:
            flush()
            level = len(heading.group(1))
            title = heading.group(2).strip()
            if level > 1:
                result.append({"kind": "heading", "level": level, "text": title})
            index += 1
            continue
        if (
            _TABLE_RE.match(line)
            and index + 1 < len(lines)
            and _TABLE_RULE_RE.match(lines[index + 1])
        ):
            flush()
            header = _table_cells(line)
            index += 2
            rows: list[list[str]] = []
            while index < len(lines) and _TABLE_RE.match(lines[index]):
                rows.append(_table_cells(lines[index]))
                index += 1
            result.append({"kind": "table", "header": header, "rows": rows})
            continue
        item = _LIST_RE.match(line)
        if item:
            flush()
            ordered = item.group(2)[0].isdigit()
            entries: list[dict[str, Any]] = []
            while index < len(lines):
                current = _LIST_RE.match(lines[index])
                if not current:
                    break
                entries.append(
                    {
                        "text": current.group(3).strip(),
                        "depth": len(current.group(1).expandtabs(4)) // 2,
                    }
                )
                index += 1
            result.append({"kind": "list", "ordered": ordered, "items": entries})
            continue
        quote = _QUOTE_RE.match(line)
        if quote:
            flush()
            quoted: list[str] = []
            while index < len(lines):
                current = _QUOTE_RE.match(lines[index])
                if not current:
                    break
                quoted.append(current.group(1).strip())
                index += 1
            result.append({"kind": "quote", "text": " ".join(quoted).strip()})
            continue
        if not line.strip():
            flush()
            index += 1
            continue
        paragraph.append(line.strip())
        index += 1
    flush()
    return result


def _table_cells(line: str) -> list[str]:
    """The cells of one markdown table row."""
    inner = line.strip().strip("|")
    return [cell.strip() for cell in inner.split("|")]


def headings(parsed: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The on-this-page list: every sub-heading with its anchor."""
    found: list[dict[str, str]] = []
    depth = 0
    for block in parsed:
        if block.get("kind") != "heading":
            continue
        depth += 1
        text = str(block.get("text") or "")
        found.append(
            {"text": text, "level": str(block.get("level") or 2), "id": _anchor(text, depth - 1)}
        )
    return found


def _page_ref(path: Path) -> dict[str, str]:
    """One page's slug and title, the pair a reader links to a neighbour with."""
    text = _read(path)
    fallback = "Changelog" if path.name == CHANGELOG_FILE else path.stem
    return {"slug": _slug_of(path), "title": _title_of(text, fallback)}


def neighbours(slug: str) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    """The page before and the page after *slug* in reading order.

    Reading order is :func:`_page_files`, the same list :func:`pages` numbers,
    so a previous/next control and the index cannot disagree.  The first page
    has no previous and the last (the changelog) has no next.  An unknown slug
    resolves to no neighbours rather than raising: the caller has already read
    the page it asked for, and a page with no neighbour is not an error.
    """
    wanted = _slug_of(_slug_path(slug))
    files = _page_files()
    ordered = [_slug_of(path) for path in files]
    if wanted not in ordered:
        return None, None
    index = ordered.index(wanted)
    previous = _page_ref(files[index - 1]) if index > 0 else None
    following = _page_ref(files[index + 1]) if index + 1 < len(ordered) else None
    return previous, following


def page(slug: str) -> dict[str, Any]:
    """One page's title, headings, blocks and its neighbours in reading order.

    Raises :class:`UnknownDocError` for an unknown slug and
    :class:`NoDocsError` when no documentation directory resolves.
    """
    path = _slug_path(slug)
    text = _read(path)
    parsed = blocks(text)
    previous, following = neighbours(slug)
    return {
        "slug": slug,
        "title": _title_of(text, path.stem),
        "headings": headings(parsed),
        "blocks": parsed,
        "previous": previous,
        "next": following,
        "source": path.name,
        "version": __version__,
    }


def excerpts() -> list[dict[str, str]]:
    """Every shipped page as ingestable text, for the knowledge scope.

    The knowledge chunker wants text rather than blocks, so a page is read
    whole and bounded by :data:`MAX_DOC_BYTES`, with its title kept as the
    document title and its filename as the source hint.  An empty result is the
    honest answer for a wheel with no documents.
    """
    found: list[dict[str, str]] = []
    for entry in _page_files():
        text = _read(entry)
        if not text.strip():
            continue
        found.append(
            {
                "slug": _slug_of(entry),
                "title": _title_of(text, entry.stem),
                "source": entry.name,
                "text": text,
            }
        )
    return found


def _page_files() -> list[Path]:
    """Every document file, in reading order: the same list :func:`pages` uses."""
    directory = documents_dir()
    if directory is None:
        return []
    available: dict[str, Path] = {}
    for path in sorted(directory.glob("*.md")):
        # The changelog is appended once via changelog_path(), whether it sits
        # beside docs/ (checkout) or inside the packaged manual/ directory.
        if path.name == CHANGELOG_FILE:
            continue
        available.setdefault(path.stem, path)
    ordered: list[Path] = []
    for stem in PAGE_ORDER:
        if stem in available:
            ordered.append(available.pop(stem))
    ordered.extend(available[stem] for stem in sorted(available))
    changelog = changelog_path()
    if changelog is not None:
        ordered.append(changelog)
    return ordered

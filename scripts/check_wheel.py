"""Assert the built wheel carries the SPA entry asset, the manual and no stale module.

The ``package-check`` target builds the wheel; this reads it back with
``zipfile`` (a wheel is a zip) and checks that ``assets/dist/index.html`` and
at least one JavaScript and one CSS bundle under ``assets/dist/assets/`` are
packaged.  A wheel without the built UI would ship a server whose SPA routes
404, so a missing asset is a hard failure rather than a warning.

It also checks that the packaged ``manual/`` directory carries every in-app
docs page: ``docs.PAGE_ORDER`` plus ``CHANGELOG.md`` plus every top-level page
and one-level subdirectory page under ``docs/``.  A wheel that omits any of
them makes ``GET /api/docs`` thin or 404 ``no-docs`` on every host without a
checkout.

It also checks that every packaged module exists in ``src/reportal``: setuptools
reuses an existing ``build/lib`` tree without pruning it, so a module deleted
from the source would otherwise keep being packaged from the stale copy.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

from reportal.docs import CHANGELOG_FILE, PAGE_ORDER

DIST_DIR = Path("dist")
WHEEL_GLOB = "reportal-*.whl"
ASSETS_PREFIX = "reportal/assets/dist/"
ENTRY_ASSET = f"{ASSETS_PREFIX}index.html"
MANUAL_PREFIX = "reportal/manual/"
MANUAL_REQUIRED = tuple(f"{MANUAL_PREFIX}{stem}.md" for stem in PAGE_ORDER) + (
    f"{MANUAL_PREFIX}{CHANGELOG_FILE}",
)
DOCS_DIR = Path("docs")
LICENSE_SUFFIX = ".dist-info/licenses/LICENSE"
PACKAGE_PREFIX = "reportal/"
SOURCE_DIR = Path("src/reportal")


def packaged_pages(docs_dir: Path = DOCS_DIR) -> tuple[str, ...]:
    """Every repository manual page, as its wheel-relative path.

    The in-app reader serves the top-level pages and one level of
    subdirectories (``subsystems/``, ``cookbook/`` and the indexes beside
    them), so a wheel that omits one serves a thinner manual than the
    checkout.  A missing ``docs/`` tree answers an empty tuple; the
    ``PAGE_ORDER`` pages are checked separately.
    """
    if not docs_dir.is_dir():
        return ()
    found: list[str] = []
    for pattern in ("*.md", "*/*.md"):
        found.extend(
            f"{MANUAL_PREFIX}{path.relative_to(docs_dir).as_posix()}"
            for path in docs_dir.glob(pattern)
        )
    return tuple(sorted(found))


def stale_modules(names: set[str]) -> list[str]:
    """Packaged ``reportal/*.py`` modules with no file in ``src/reportal``."""
    packaged = {
        name
        for name in names
        if name.startswith(PACKAGE_PREFIX)
        and name.endswith(".py")
        and "/" not in name[len(PACKAGE_PREFIX) :]
    }
    missing = [
        name for name in packaged if not (SOURCE_DIR / name[len(PACKAGE_PREFIX) :]).is_file()
    ]
    return sorted(missing)


def missing_manual(names: set[str], required: tuple[str, ...] = MANUAL_REQUIRED) -> list[str]:
    """Required packaged-manual paths absent from the wheel."""
    return [path for path in required if path not in names]


def newest_wheel(dist_dir: Path = DIST_DIR) -> Path | None:
    """The most recently modified ``reportal-*.whl`` under *dist_dir*, if any."""
    wheels = list(dist_dir.glob(WHEEL_GLOB))
    if not wheels:
        return None
    return max(wheels, key=lambda path: path.stat().st_mtime)


def main() -> int:
    """Verify the newest wheel in ``dist/`` carries the built SPA and no stale module."""
    wheel = newest_wheel()
    if wheel is None:
        sys.stderr.write(f"no {WHEEL_GLOB} in {DIST_DIR}/; run `uv build --wheel` first\n")
        return 1
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    stale = stale_modules(names)
    if stale:
        sys.stderr.write(
            f"{wheel.name} packages modules missing from {SOURCE_DIR}/: {', '.join(stale)}\n"
            "a stale build/lib tree is being reused; remove it with `make clean`\n"
        )
        return 1
    bundles = [name for name in names if name.startswith(f"{ASSETS_PREFIX}assets/")]
    js = [name for name in bundles if name.endswith(".js")]
    css = [name for name in bundles if name.endswith(".css")]
    gz = [name for name in bundles if name.endswith((".js.gz", ".css.gz"))]
    has_license = any(name.endswith(LICENSE_SUFFIX) for name in names)
    required = tuple(dict.fromkeys(MANUAL_REQUIRED + packaged_pages()))
    manual_gaps = missing_manual(names, required)
    missing = [
        label
        for label, present in (
            (ENTRY_ASSET, ENTRY_ASSET in names),
            ("an assets/*.js bundle", bool(js)),
            ("an assets/*.css bundle", bool(css)),
            ("an assets/*.js.gz or *.css.gz sibling", bool(gz)),
            (f"*{LICENSE_SUFFIX}", has_license),
            *((path, path in names) for path in required),
        )
        if not present
    ]
    if missing:
        hint = ""
        if manual_gaps:
            hint = "; run `scripts/sync_packaged_docs.py` before `uv build`"
        sys.stderr.write(f"{wheel.name} is missing: {', '.join(missing)}{hint}\n")
        return 1
    manual_count = sum(
        1 for name in names if name.startswith(MANUAL_PREFIX) and name.endswith(".md")
    )
    sys.stdout.write(
        f"{wheel.name}: {ENTRY_ASSET}, {len(js)} JS, {len(css)} CSS, "
        f"{len(gz)} gzip asset(s), {manual_count} manual page(s) packaged\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

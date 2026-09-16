"""Assert the built wheel carries the SPA entry asset, the manual and no stale module.

The ``package-check`` target builds the wheel; this reads it back with
``zipfile`` (a wheel is a zip) and checks that ``assets/dist/index.html`` and
at least one JavaScript and one CSS bundle under ``assets/dist/assets/`` are
packaged.  A wheel without the built UI would ship a server whose SPA routes
404, so a missing asset is a hard failure rather than a warning.

It also checks that the packaged ``manual/`` directory carries the in-app docs
(``ERRORS.md`` and ``CHANGELOG.md`` at minimum): a wheel that omits them makes
``GET /api/docs`` answer 404 ``no-docs`` on every host without a checkout.

It also checks that every packaged module exists in ``src/reportal``: setuptools
reuses an existing ``build/lib`` tree without pruning it, so a module deleted
from the source would otherwise keep being packaged from the stale copy.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

DIST_DIR = Path("dist")
WHEEL_GLOB = "reportal-*.whl"
ASSETS_PREFIX = "reportal/assets/dist/"
ENTRY_ASSET = f"{ASSETS_PREFIX}index.html"
MANUAL_PREFIX = "reportal/manual/"
MANUAL_REQUIRED = (
    f"{MANUAL_PREFIX}ERRORS.md",
    f"{MANUAL_PREFIX}CHANGELOG.md",
)
PACKAGE_PREFIX = "reportal/"
SOURCE_DIR = Path("src/reportal")


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


def missing_manual(names: set[str]) -> list[str]:
    """Required packaged-manual paths absent from the wheel."""
    return [path for path in MANUAL_REQUIRED if path not in names]


def main() -> int:
    """Verify the newest wheel in ``dist/`` carries the built SPA and no stale module."""
    wheels = sorted(DIST_DIR.glob(WHEEL_GLOB))
    if not wheels:
        sys.stderr.write(f"no {WHEEL_GLOB} in {DIST_DIR}/; run `uv build --wheel` first\n")
        return 1
    wheel = wheels[-1]
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
    manual_gaps = missing_manual(names)
    missing = [
        label
        for label, present in (
            (ENTRY_ASSET, ENTRY_ASSET in names),
            ("an assets/*.js bundle", bool(js)),
            ("an assets/*.css bundle", bool(css)),
            ("an assets/*.js.gz or *.css.gz sibling", bool(gz)),
            *((path, path in names) for path in MANUAL_REQUIRED),
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

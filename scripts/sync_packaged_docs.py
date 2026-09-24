#!/usr/bin/env python3
"""Copy the repository manual into ``src/reportal/manual`` for the wheel.

``docs.py`` resolves an installed wheel's in-app manual from this directory.
The repository's ``docs/`` tree and ``CHANGELOG.md`` stay the source of truth;
this step mirrors them, subdirectories included, into the package tree so
``package-data`` can ship them.
"""

from __future__ import annotations

import sys
from pathlib import Path

from reportal.docs import CHANGELOG_FILE, PAGE_ORDER, REPOSITORY_ONLY_PAGES

REPO = Path(__file__).resolve().parents[1]
DOCS_SRC = REPO / "docs"
CHANGELOG_SRC = REPO / "CHANGELOG.md"
DEST = REPO / "src" / "reportal" / "manual"


def sync(dest: Path = DEST, docs_src: Path = DOCS_SRC, changelog: Path = CHANGELOG_SRC) -> int:
    """Mirror markdown docs into *dest*; return how many files were written.

    Returns ``-1`` when a ``PAGE_ORDER`` page is missing from *docs_src*, so the
    wheel cannot ship an incomplete in-app manual.
    """
    if not docs_src.is_dir():
        sys.stderr.write(f"no documentation directory at {docs_src}\n")
        return -1
    wanted: dict[str, Path] = {}
    for pattern in ("*.md", "*/*.md"):
        for path in sorted(docs_src.glob(pattern)):
            if path.is_file() and not (pattern == "*.md" and path.stem in REPOSITORY_ONLY_PAGES):
                wanted[path.relative_to(docs_src).as_posix()] = path
    if changelog.is_file():
        wanted[changelog.name] = changelog
    required = [f"{stem}.md" for stem in PAGE_ORDER]
    gaps = [name for name in required if name not in wanted]
    if CHANGELOG_FILE not in wanted:
        gaps.append(CHANGELOG_FILE)
    if gaps:
        sys.stderr.write(
            f"packaged manual is incomplete under {docs_src}: missing {', '.join(gaps)}\n"
        )
        return -1
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, source in wanted.items():
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = source.read_bytes()
        if target.is_file() and target.read_bytes() == payload:
            continue
        target.write_bytes(payload)
        written += 1
        sys.stdout.write(f"{name}\n")
    for pattern in ("*.md", "*/*.md"):
        for stale in sorted(dest.glob(pattern)):
            if stale.relative_to(dest).as_posix() not in wanted:
                stale.unlink()
                sys.stdout.write(f"removed stale {stale.relative_to(dest).as_posix()}\n")
    for directory in sorted(dest.glob("*/")):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    return written


def main() -> int:
    """Sync the packaged manual; exit 1 when the source docs directory is missing."""
    if not DOCS_SRC.is_dir():
        sys.stderr.write(f"no documentation directory at {DOCS_SRC}\n")
        return 1
    count = sync()
    if count < 0:
        return 1
    sys.stdout.write(f"synced {count} file(s) into {DEST}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

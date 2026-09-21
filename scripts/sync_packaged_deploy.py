#!/usr/bin/env python3
"""Copy systemd unit templates into ``src/reportal/deploy`` for the wheel.

``deploy/`` at the repository root stays the source of truth operators edit.
This step mirrors the unit templates into the package tree so ``package-data``
ships them: a wheel install has no checkout, and without this copy
``reportal deploy-units`` and the Deploy docs would point at nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from reportal.doctor import DEPLOY_UNIT_FILES

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "deploy"
DEST = REPO / "src" / "reportal" / "deploy"

# Names the wheel must carry; single source of truth is ``doctor.DEPLOY_UNIT_FILES``.
REQUIRED: tuple[str, ...] = DEPLOY_UNIT_FILES


def sync(dest: Path = DEST, source: Path = SOURCE) -> int:
    """Mirror unit templates into *dest*; return how many files were written.

    Returns ``-1`` when a required unit is missing from *source*, so the wheel
    cannot ship an incomplete deploy set.
    """
    if not source.is_dir():
        sys.stderr.write(f"no deploy directory at {source}\n")
        return -1
    wanted: dict[str, Path] = {}
    for name in REQUIRED:
        path = source / name
        if path.is_file():
            wanted[name] = path
    gaps = [name for name in REQUIRED if name not in wanted]
    if gaps:
        sys.stderr.write(
            f"packaged deploy units incomplete under {source}: missing {', '.join(gaps)}\n"
        )
        return -1
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    for name, path in wanted.items():
        target = dest / name
        payload = path.read_bytes()
        if target.is_file() and target.read_bytes() == payload:
            continue
        target.write_bytes(payload)
        written += 1
        sys.stdout.write(f"{name}\n")
    for stale in sorted(dest.iterdir()):
        if stale.is_file() and stale.name not in wanted:
            stale.unlink()
            sys.stdout.write(f"removed stale {stale.name}\n")
    return written


def main() -> int:
    """Sync the packaged deploy units; exit 1 when the source set is incomplete."""
    count = sync()
    if count < 0:
        return 1
    sys.stdout.write(f"synced {count} file(s) into {DEST}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

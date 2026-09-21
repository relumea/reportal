"""Assert the built sdist carries deploy units and no SPA contamination.

The ``package-check`` target builds the sdist after the wheel; this reads it
back with ``tarfile`` and checks that the root ``deploy/`` templates
(``doctor.DEPLOY_UNIT_FILES``) are present, that ``LICENSE`` /
``pyproject.toml`` / ``MANIFEST.in`` / ``README.md`` ship, and that
``__pycache__``, source maps, and host-dependent ``*.br`` siblings stay out.
An sdist that embeds ``*.br`` reintroduces the host-dependent wheel failure
``scripts/check_wheel.py`` already guards.

setuptools always embeds a generated ``*.egg-info/`` tree in the sdist; that
is backend metadata and is not flagged here.
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

from reportal.doctor import DEPLOY_UNIT_FILES

DIST_DIR = Path("dist")
SDIST_GLOB = "reportal-*.tar.gz"
DEPLOY_REQUIRED = tuple(f"deploy/{name}" for name in DEPLOY_UNIT_FILES)
ROOT_REQUIRED = ("LICENSE", "pyproject.toml", "MANIFEST.in", "README.md")


def newest_sdist(dist_dir: Path = DIST_DIR) -> Path | None:
    """The most recently modified ``reportal-*.tar.gz`` under *dist_dir*, if any."""
    archives = list(dist_dir.glob(SDIST_GLOB))
    if not archives:
        return None
    return max(archives, key=lambda path: path.stat().st_mtime)


def member_relpaths(archive: tarfile.TarFile) -> set[str]:
    """Archive member paths with the leading ``reportal-<version>/`` stripped."""
    relpaths: set[str] = set()
    for name in archive.getnames():
        parts = name.split("/", 1)
        if len(parts) == 2 and parts[1]:
            relpaths.add(parts[1])
        elif len(parts) == 1 and parts[0] and not parts[0].endswith("/"):
            relpaths.add(parts[0])
    return relpaths


def contamination(names: set[str]) -> list[str]:
    """Packaged paths that must never appear in an sdist."""
    bad: list[str] = []
    for name in sorted(names):
        lowered = name.lower()
        if "/__pycache__/" in lowered or lowered.endswith(
            (".br", ".map", ".map.gz", ".pyc", ".pyo")
        ):
            bad.append(name)
    return bad


def missing_required(names: set[str]) -> list[str]:
    """Required root and deploy paths absent from the sdist."""
    wanted = list(ROOT_REQUIRED) + list(DEPLOY_REQUIRED)
    return [path for path in wanted if path not in names]


def main() -> int:
    """Verify the newest sdist in ``dist/`` is complete and uncontaminated."""
    sdist = newest_sdist()
    if sdist is None:
        sys.stderr.write(f"no {SDIST_GLOB} in {DIST_DIR}/; run `uv build --sdist` first\n")
        return 1
    with tarfile.open(sdist, "r:gz") as archive:
        names = member_relpaths(archive)
    bad = contamination(names)
    if bad:
        shown = ", ".join(bad[:8])
        more = f" (+{len(bad) - 8} more)" if len(bad) > 8 else ""
        sys.stderr.write(
            f"{sdist.name} packages host-dependent or bytecode assets: "
            f"{shown}{more}\n"
            "exclude *.br / *.map / __pycache__ via MANIFEST.in\n"
        )
        return 1
    gaps = missing_required(names)
    if gaps:
        sys.stderr.write(f"{sdist.name} is missing: {', '.join(gaps)}\n")
        return 1
    sys.stdout.write(
        f"{sdist.name}: {len(DEPLOY_REQUIRED)} deploy unit(s), "
        f"{len(ROOT_REQUIRED)} root metadata file(s), no br/map/bytecode\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

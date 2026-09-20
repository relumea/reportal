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

It also checks that the packaged ``deploy/`` directory carries every systemd
unit template (``doctor.DEPLOY_UNIT_FILES``).  A wheel without them leaves a
``pip install`` host with no unit file to copy, even though Deploy docs assume
one.

It also checks that every packaged module exists in ``src/reportal``: setuptools
reuses an existing ``build/lib`` tree without pruning it, so a module deleted
from the source would otherwise keep being packaged from the stale copy.

Gzip siblings must carry a reproducible header mtime (``SOURCE_DATE_EPOCH`` when
set, else ``0``), every zip member's DOS ``date_time`` must match that epoch,
and the wheel must not ship ``*.map`` source maps or host-dependent ``*.br``
siblings.  METADATA must declare every base runtime dependency named in
``REQUIRED_DIST_NAMES`` so a clean install still has the FLIRT matcher and the
HTTP/API stack the portal imports at module scope.
"""

from __future__ import annotations

import os
import struct
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from reportal.docs import CHANGELOG_FILE, PAGE_ORDER
from reportal.doctor import DEPLOY_UNIT_FILES

DIST_DIR = Path("dist")
WHEEL_GLOB = "reportal-*.whl"
ASSETS_PREFIX = "reportal/assets/dist/"
ENTRY_ASSET = f"{ASSETS_PREFIX}index.html"
MANUAL_PREFIX = "reportal/manual/"
MANUAL_REQUIRED = tuple(f"{MANUAL_PREFIX}{stem}.md" for stem in PAGE_ORDER) + (
    f"{MANUAL_PREFIX}{CHANGELOG_FILE}",
)
DEPLOY_PREFIX = "reportal/deploy/"
DEPLOY_REQUIRED = tuple(f"{DEPLOY_PREFIX}{name}" for name in DEPLOY_UNIT_FILES)
DOCS_DIR = Path("docs")
LICENSE_SUFFIX = ".dist-info/licenses/LICENSE"
PACKAGE_PREFIX = "reportal/"
SOURCE_DIR = Path("src/reportal")
# Base ``[project] dependencies`` that must appear as Requires-Dist.  Optional
# extras are gated separately; path-sourced siblings (``rebrew``) stay unpinned.
REQUIRED_DIST_NAMES = (
    "anyio",
    "fastapi",
    "httpx2",
    "mcp",
    "openai",
    "python-multipart",
    "python-flirt",
    "rebrew",
    "reportlab",
    "rich",
    "starlette",
    "typer",
    "uvicorn",
)


def expected_gzip_mtime() -> int:
    """Gzip header mtime the build must embed: ``SOURCE_DATE_EPOCH`` or ``0``."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return 0
    return max(value, 0)


def gzip_member_mtime(payload: bytes) -> int | None:
    """Little-endian mtime from a gzip member header, or None when not gzip."""
    if len(payload) < 8 or payload[:2] != b"\x1f\x8b":
        return None
    return int(struct.unpack_from("<I", payload, 4)[0])


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


def missing_deploy(names: set[str], required: tuple[str, ...] = DEPLOY_REQUIRED) -> list[str]:
    """Required packaged systemd unit paths absent from the wheel."""
    return [path for path in required if path not in names]


def missing_requires_dist(
    metadata: str, required: tuple[str, ...] = REQUIRED_DIST_NAMES
) -> list[str]:
    """Declared runtime dependency names absent from wheel METADATA."""
    declared: set[str] = set()
    for line in metadata.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        rest = line.split(":", 1)[1].strip()
        name = rest.split(";", 1)[0].strip()
        for sep in ("(", "[", " ", "<", ">", "=", "!"):
            if sep in name:
                name = name.split(sep, 1)[0].strip()
        if name:
            declared.add(name.lower())
    return [name for name in required if name.lower() not in declared]


def source_maps(names: set[str]) -> list[str]:
    """Packaged ``*.map`` paths under the SPA dist (release contamination)."""
    return sorted(
        name for name in names if name.startswith(ASSETS_PREFIX) and name.endswith(".map")
    )


def brotli_siblings(names: set[str]) -> list[str]:
    """Packaged ``*.br`` paths under the SPA dist (host-dependent contamination)."""
    return sorted(name for name in names if name.startswith(ASSETS_PREFIX) and name.endswith(".br"))


def expected_zip_date_time(epoch: int | None = None) -> tuple[int, int, int, int, int, int]:
    """Zip DOS ``date_time`` setuptools embeds for ``SOURCE_DATE_EPOCH``.

    Zip cannot express times before 1980-01-01; a zero or pre-1980 epoch clamps
    to that floor.  Seconds are even (DOS two-second resolution).
    """
    value = expected_gzip_mtime() if epoch is None else max(int(epoch), 0)
    if value == 0:
        return (1980, 1, 1, 0, 0, 0)
    instant = datetime.fromtimestamp(value, tz=UTC)
    if instant.year < 1980:
        return (1980, 1, 1, 0, 0, 0)
    second = instant.second - (instant.second % 2)
    return (instant.year, instant.month, instant.day, instant.hour, instant.minute, second)


def nondeterministic_zip_dates(
    archive: zipfile.ZipFile, *, expected: tuple[int, int, int, int, int, int]
) -> list[str]:
    """Member paths whose zip ``date_time`` is not the reproducible epoch."""
    return sorted(info.filename for info in archive.infolist() if info.date_time != expected)


def nondeterministic_gzip(
    archive: zipfile.ZipFile, names: set[str], *, expected_mtime: int
) -> list[str]:
    """Gzip asset paths whose header mtime is not the reproducible epoch."""
    bad: list[str] = []
    for name in sorted(names):
        if not (name.startswith(ASSETS_PREFIX) and name.endswith(".gz")):
            continue
        mtime = gzip_member_mtime(archive.read(name))
        if mtime is None or mtime != expected_mtime:
            bad.append(name)
    return bad


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
    expected_mtime = expected_gzip_mtime()
    expected_date = expected_zip_date_time(expected_mtime)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        gzip_bad = nondeterministic_gzip(archive, names, expected_mtime=expected_mtime)
        zip_bad = nondeterministic_zip_dates(archive, expected=expected_date)
        metadata_name = next(
            (name for name in names if name.endswith(".dist-info/METADATA")),
            "",
        )
        metadata = archive.read(metadata_name).decode() if metadata_name else ""
    stale = stale_modules(names)
    if stale:
        sys.stderr.write(
            f"{wheel.name} packages modules missing from {SOURCE_DIR}/: {', '.join(stale)}\n"
            "a stale build/lib tree is being reused; remove it with `make clean`\n"
        )
        return 1
    maps = source_maps(names)
    if maps:
        sys.stderr.write(
            f"{wheel.name} packages source maps (release contamination): {', '.join(maps)}\n"
        )
        return 1
    br = brotli_siblings(names)
    if br:
        sys.stderr.write(
            f"{wheel.name} packages brotli siblings (host-dependent): {', '.join(br)}\n"
            "rebuild with REPORTAL_BROTLI=0 (make package-wheel)\n"
        )
        return 1
    if gzip_bad:
        sys.stderr.write(
            f"{wheel.name} has gzip siblings with non-reproducible mtime: "
            f"{', '.join(gzip_bad)}\n"
            "rebuild with SOURCE_DATE_EPOCH set (make package-check)\n"
        )
        return 1
    if zip_bad:
        shown = ", ".join(zip_bad[:8])
        more = f" (+{len(zip_bad) - 8} more)" if len(zip_bad) > 8 else ""
        sys.stderr.write(
            f"{wheel.name} has zip members with non-reproducible date_time "
            f"(want {expected_date}): {shown}{more}\n"
            "rebuild with SOURCE_DATE_EPOCH set (make package-check)\n"
        )
        return 1
    dep_gaps = missing_requires_dist(metadata)
    if dep_gaps:
        sys.stderr.write(f"{wheel.name} METADATA is missing Requires-Dist: {', '.join(dep_gaps)}\n")
        return 1
    bundles = [name for name in names if name.startswith(f"{ASSETS_PREFIX}assets/")]
    js = [name for name in bundles if name.endswith(".js")]
    css = [name for name in bundles if name.endswith(".css")]
    gz = [name for name in bundles if name.endswith((".js.gz", ".css.gz"))]
    has_license = any(name.endswith(LICENSE_SUFFIX) for name in names)
    required = tuple(dict.fromkeys(MANUAL_REQUIRED + packaged_pages()))
    manual_gaps = missing_manual(names, required)
    deploy_gaps = missing_deploy(names)
    missing = [
        label
        for label, present in (
            (ENTRY_ASSET, ENTRY_ASSET in names),
            ("an assets/*.js bundle", bool(js)),
            ("an assets/*.css bundle", bool(css)),
            ("an assets/*.js.gz or *.css.gz sibling", bool(gz)),
            (f"*{LICENSE_SUFFIX}", has_license),
            *((path, path in names) for path in required),
            *((path, path in names) for path in DEPLOY_REQUIRED),
        )
        if not present
    ]
    if missing:
        hint = ""
        if manual_gaps:
            hint = "; run `scripts/sync_packaged_docs.py` before `uv build`"
        elif deploy_gaps:
            hint = "; run `scripts/sync_packaged_deploy.py` before `uv build`"
        sys.stderr.write(f"{wheel.name} is missing: {', '.join(missing)}{hint}\n")
        return 1
    manual_count = sum(
        1 for name in names if name.startswith(MANUAL_PREFIX) and name.endswith(".md")
    )
    sys.stdout.write(
        f"{wheel.name}: {ENTRY_ASSET}, {len(js)} JS, {len(css)} CSS, "
        f"{len(gz)} gzip asset(s), {manual_count} manual page(s), "
        f"{len(DEPLOY_REQUIRED)} deploy unit(s) packaged\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

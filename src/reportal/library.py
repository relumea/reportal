"""Library identification and the software bill of materials it feeds.

The engine answers one question: which of a binary's functions came from a
known library.  Its own `identify_library` call reports matches by virtual
address with a module name, a kind and a confidence, and reportal ran it only
as the first half of auto-unstrip, throwing the module away and keeping just the
rename proposals.

This module keeps the identification itself: the stored `library` scan carries
the candidates grouped by module with their function counts and byte totals, so
a reader can see what a binary is built from rather than only what it could be
renamed to.  :func:`run_library` is the one write path (the routes, the CLI and
the MCP tool share it), and :func:`sbom` renders the stored scan as a component
list in one of the published bill-of-materials shapes.

Nothing here is a new signal.  A module name comes from the engine's signature
match, so a module the engine does not know is absent rather than guessed at,
and the payload says so in its notes.  No network call, no execution and no
engine work beyond the one identification the caller asked for.
"""

from __future__ import annotations

import csv
import io
import sqlite3
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from reportal import __version__, store
from reportal.engines import RebrewEngine

# The scan kind the identification is stored under.  Listed as
# `store.SCAN_KIND_LIBRARY` so the ratings vocabulary picks it up.
SCAN_KIND = store.SCAN_KIND_LIBRARY

# Formats `sbom` can render: the two published bill-of-materials shapes and a
# flat component list for a spreadsheet.
FORMAT_CYCLONEDX = "cyclonedx"
FORMAT_SPDX = "spdx"
FORMAT_CSV = "csv"
SBOM_FORMATS: tuple[str, ...] = (FORMAT_CYCLONEDX, FORMAT_SPDX, FORMAT_CSV)

# Minimum engine confidence a module must reach when the caller names none.
# Import matches carry 0.3, the lowest the engine reports, so 0.0 keeps every
# candidate by default; the caller narrows it when the corpus is noisy.
DEFAULT_MIN_CONFIDENCE = 0.0

# Module name a candidate with none is reported under, so a component list adds
# up to the candidate count instead of dropping the anonymous ones.
UNKNOWN_MODULE = "unknown"

# Components the payload returns.  A statically linked binary can match hundreds
# of modules; every count stays exact when the list is capped and the note
# states the cap.
MAX_COMPONENTS = 500

# CycloneDX and SPDX shapes the exporter declares.  Both are the current
# published revisions at the time of writing; the document carries the version
# so a consumer reads it the way the schema says.
CYCLONEDX_SPEC_VERSION = "1.5"
SPDX_VERSION = "SPDX-2.3"
SPDX_LICENSE = "NOASSERTION"

IdentifyFn = Callable[[str | Path], dict[str, Any]]

# Detail a run with no stored project context reports.
NO_CONTEXT_DETAIL = "binary {} has no rebrew project context; run 'reportal import-rebrew' first"


class LibraryError(Exception):
    """The identification cannot run: no project context, or an engine failure."""

    code = "no-engine-context"

    def __init__(self, detail: str, code: str = "no-engine-context") -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _candidate_va(raw: Any) -> int | None:
    """A candidate's VA as an int: a hex string from the engine, or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw, 16)
        except ValueError:
            return None
    return None


def _confidence(raw: Any) -> float:
    """A candidate's confidence as a float in `0..1`."""
    if isinstance(raw, bool):
        return 0.0
    if isinstance(raw, (int, float)):
        return max(0.0, min(1.0, float(raw)))
    return 0.0


def _text(raw: Any, fallback: str) -> str:
    """One candidate field as a non-empty string, or *fallback*."""
    value = str(raw or "").strip()
    return value or fallback


def proposals(result: dict[str, Any], functions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The engine's candidates, joined to the stored functions and sorted.

    A candidate whose VA is not a stored function is kept: the identification
    is a statement about the binary, not about reportal's function table, and
    dropping it would make the component list understate what the engine found.
    The join only adds the stored function id and size when one exists, which is
    what lets a reader open the function a component was identified from.
    """
    by_va = {int(function["va"]): function for function in functions}
    raw = result.get("candidates")
    candidates = raw if isinstance(raw, list) else []
    found: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        va = _candidate_va(candidate.get("va"))
        if va is None:
            continue
        function = by_va.get(va)
        found.append(
            {
                "va": f"0x{va:08x}",
                "name": _text(candidate.get("name"), f"sub_{va:x}"),
                "module": _text(candidate.get("module"), UNKNOWN_MODULE),
                "kind": _text(candidate.get("kind"), "unknown"),
                "confidence": round(_confidence(candidate.get("confidence")), 2),
                "function_id": None if function is None else int(function["id"]),
                "size": 0 if function is None else int(function["size"]),
            }
        )
    found.sort(key=lambda entry: (-float(entry["confidence"]), str(entry["va"])))
    return found


def components(
    candidates: Sequence[dict[str, Any]], *, limit: int = MAX_COMPONENTS
) -> list[dict[str, Any]]:
    """One component per module, most functions first.

    A component carries the module, the kinds the engine matched in it (sorted,
    deduplicated), how many functions it covers, their total byte size and the
    best confidence any of its matches reached, which is what a reader wants
    before deciding whether a module is really there.
    """
    rollup: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        module = str(candidate["module"])
        entry = rollup.setdefault(
            module,
            {
                "module": module,
                "kinds": set(),
                "functions": 0,
                "size": 0,
                "confidence": 0.0,
                "linkage": "static",
            },
        )
        entry["kinds"].add(str(candidate["kind"]))
        entry["functions"] += 1
        entry["size"] += int(candidate["size"])
        entry["confidence"] = max(float(entry["confidence"]), float(candidate["confidence"]))
    found = [
        {
            "module": entry["module"],
            "kinds": sorted(entry["kinds"]),
            "functions": entry["functions"],
            "size": entry["size"],
            "confidence": round(float(entry["confidence"]), 2),
            "linkage": entry["linkage"],
        }
        for entry in rollup.values()
    ]
    found.sort(key=lambda entry: (-int(entry["functions"]), str(entry["module"])))
    return found[:limit]


def describe(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The stored identification of one binary, or an empty reading.

    Raises :class:`LibraryError` for an unknown binary.  A binary with no
    stored scan answers `stored: false` and an empty component list rather than
    a 404, because "this binary was never identified" and "nothing was found"
    are answers a caller can act on, and the command that fills it is named.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise LibraryError(f"no binary with id {binary_id}", code="binary not found")
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    stored = None if analysis_id is None else store.get_scan(conn, analysis_id, SCAN_KIND)
    if stored is None:
        return {
            "binary_id": binary_id,
            "binary_name": str(binary["name"]),
            "stored": False,
            "components": [],
            "count": 0,
            "candidates": 0,
            "notes": [f"no stored library scan; run 'reportal library {binary_id}'"],
        }
    return stored


def run_library(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RebrewEngine | None,
    ident: IdentifyFn | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> dict[str, Any]:
    """Identify a binary's library functions and store the reading.

    The engine runs in the binary's stored rebrew project context, which must
    exist; *ident* overrides the identification call and defaults to
    :meth:`RebrewEngine.identify_library`, so a caller that injects the call may
    pass no engine at all.  Candidates below *min_confidence* are
    dropped before the scan is stored, and the components are derived from what
    survives, so the cap and the threshold cannot disagree with each other.

    Raises :class:`LibraryError` without a stored project context and propagates
    an engine failure.
    """
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise LibraryError(NO_CONTEXT_DETAIL.format(binary_id))
    if ident is None and engine is None:
        raise LibraryError(NO_CONTEXT_DETAIL.format(binary_id))
    identify: IdentifyFn = ident if ident is not None else engine.identify_library  # type: ignore[union-attr]
    result = identify(project_dir)
    functions = store.list_functions(conn, binary_id=binary_id)
    kept = [
        candidate
        for candidate in proposals(result, functions)
        if float(candidate["confidence"]) >= min_confidence
    ]
    found = components(kept)
    notes = [
        (
            "library identification from the engine's own signature match; a module"
            " the engine does not know is absent rather than guessed at"
        )
    ]
    if min_confidence > 0:
        notes.append(f"candidates below confidence {min_confidence} were dropped")
    if len(found) == MAX_COMPONENTS:
        notes.append(f"showing the {MAX_COMPONENTS} modules with the most functions")
    payload = {
        "binary_id": binary_id,
        "stored": True,
        "components": found,
        "count": len(found),
        "candidates": len(kept),
        "identified": int(result.get("identified") or len(kept)),
        "already_annotated": int(result.get("already_annotated") or 0),
        "min_confidence": min_confidence,
        "functions": kept,
        "notes": notes,
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, SCAN_KIND, payload, params={"min_confidence": min_confidence})
    return payload


def _binary_purl(name: str, sha256: str) -> str:
    """The package URL of the analysed binary itself."""
    return f"pkg:generic/{name}@{sha256[:12] or 'unknown'}"


def _component_purl(module: str) -> str:
    """A module's package URL.  The engine reports a name, not a version, so the
    version is left out rather than invented."""
    return f"pkg:generic/{module}"


def _go_purl(module: str, version: str) -> str:
    """A Go dependency's package URL, with the pinned version it declares."""
    purl = f"pkg:golang/{module.strip('/')}"
    return f"{purl}@{version}" if version else purl


def _go_components(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """The stored gobuildinfo dependencies as SBOM components, or empty.

    A component carries the module, its pinned version, the Go purl, the
    `go-module` kind and zeroed engine counts: the buildinfo names versions,
    not functions, so the counts are honestly zero rather than invented.
    """
    from reportal import details, gobuildinfo

    scan = details.stored_scan(conn, binary_id, gobuildinfo.SCAN_KIND)
    dependencies = scan.get("dependencies") if isinstance(scan, dict) else None
    if not isinstance(dependencies, list):
        return []
    found: list[dict[str, Any]] = []
    for entry in dependencies:
        if not isinstance(entry, dict):
            continue
        module = str(entry.get("module") or "").strip()
        version = str(entry.get("version") or "").strip()
        if not module:
            continue
        found.append(
            {
                "module": module,
                "kinds": ["go-module"],
                "functions": 0,
                "size": 0,
                "confidence": 1.0,
                "linkage": "static",
                "version": version,
                "source": gobuildinfo.SCAN_KIND,
            }
        )
    return found


def sbom(
    conn: sqlite3.Connection, binary_id: int, *, fmt: str = FORMAT_CYCLONEDX
) -> dict[str, Any]:
    """Render a stored identification as a component list.

    Returns a document dict for the two schema shapes and a `{"columns",
    "rows"}` table for CSV.  Raises :class:`LibraryError` for an unknown binary
    and :class:`ValueError` for an unknown format.  The reading always comes
    from the stored scans (the library identification plus the gobuildinfo
    dependencies, when that scan exists), so exporting never runs the engine
    again.
    """
    if fmt not in SBOM_FORMATS:
        raise ValueError(f"unknown format: {fmt}; expected one of {', '.join(SBOM_FORMATS)}")
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise LibraryError(f"no binary with id {binary_id}", code="binary not found")
    stored = describe(conn, binary_id)
    found = stored.get("components") or []
    go = _go_components(conn, binary_id)
    name = str(binary["name"])
    sha256 = str(binary.get("sha256") or "")
    if fmt == FORMAT_CSV:
        return {
            "format": fmt,
            "columns": ["module", "kinds", "functions", "size", "confidence", "linkage"],
            "rows": [
                {
                    "module": str(entry["module"]),
                    "kinds": " ".join(str(kind) for kind in entry["kinds"]),
                    "functions": int(entry["functions"]),
                    "size": int(entry["size"]),
                    "confidence": float(entry["confidence"]),
                    "linkage": str(entry["linkage"]),
                }
                for entry in [*found, *go]
            ],
        }
    if fmt == FORMAT_CYCLONEDX:
        return {
            "format": fmt,
            "document": {
                "bomFormat": "CycloneDX",
                "specVersion": CYCLONEDX_SPEC_VERSION,
                "version": 1,
                "metadata": {
                    "timestamp": store.now(),
                    "tools": [{"vendor": "reportal", "name": "reportal", "version": __version__}],
                    "component": {
                        "type": "application",
                        "name": name,
                        "version": sha256,
                        "purl": _binary_purl(name, sha256),
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "name": str(entry["module"]),
                        "purl": _component_purl(str(entry["module"])),
                        "properties": _component_properties(entry),
                    }
                    for entry in found
                ]
                + [
                    {
                        "type": "library",
                        "name": str(entry["module"]),
                        "version": str(entry.get("version") or ""),
                        "purl": _go_purl(str(entry["module"]), str(entry.get("version") or "")),
                        "properties": _component_properties(entry),
                    }
                    for entry in go
                ],
            },
        }
    offset = len(found)
    return {
        "format": fmt,
        "document": {
            "spdxVersion": SPDX_VERSION,
            "dataLicense": SPDX_LICENSE,
            "name": f"{name}-{sha256[:12]}",
            "documentNamespace": f"https://reportal.invalid/spdx/{sha256 or binary_id}",
            "creationInfo": {
                "created": store.now(),
                "creators": [f"Tool: reportal-{__version__}"],
            },
            "packages": [
                {
                    "name": name,
                    "SPDXID": "SPDXRef-Package-binary",
                    "versionInfo": sha256,
                    "downloadLocation": SPDX_LICENSE,
                    "filesAnalyzed": False,
                },
                *[
                    {
                        "name": str(entry["module"]),
                        "SPDXID": f"SPDXRef-Package-{index}",
                        "versionInfo": "",
                        "downloadLocation": SPDX_LICENSE,
                        "filesAnalyzed": False,
                    }
                    for index, entry in enumerate(found, start=1)
                ],
                *[
                    {
                        "name": str(entry["module"]),
                        "SPDXID": f"SPDXRef-Package-{index}",
                        "versionInfo": str(entry.get("version") or ""),
                        "downloadLocation": SPDX_LICENSE,
                        "filesAnalyzed": False,
                    }
                    for index, entry in enumerate(go, start=offset + 1)
                ],
            ],
        },
    }


def _component_properties(entry: dict[str, Any]) -> list[dict[str, str]]:
    """The reportal-specific facts a CycloneDX component carries."""
    return [
        {"name": "reportal:functions", "value": str(int(entry["functions"]))},
        {"name": "reportal:size", "value": str(int(entry["size"]))},
        {"name": "reportal:confidence", "value": str(float(entry["confidence"]))},
        {"name": "reportal:linkage", "value": str(entry["linkage"])},
        {"name": "reportal:kinds", "value": " ".join(str(kind) for kind in entry["kinds"])},
    ]


def render_csv(payload: dict[str, Any]) -> str:
    """Render a CSV export as text, header first."""
    buffer = io.StringIO()
    columns = [str(column) for column in payload["columns"]]
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in payload["rows"]:
        writer.writerow(row)
    return buffer.getvalue()

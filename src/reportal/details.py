"""The binary-detail reads the hosted portal derives from a scan.

Two of the hosted ``Binaries`` reads are pure derivations rather than engine
calls, and this module derives them locally from what reportal already stored,
so neither runs the engine, touches the network or writes anything:

- :func:`die_info` is the Detect-It-Easy identity: what the file is (format,
  architecture, bit width, entry point, subsystem) beside what was found inside
  it (packer, protector, installer, runtime, toolchain), each with the file-type
  scan's confidence and the signals that matched, plus the entropy the
  fingerprint carries.  DIE carries a much larger signature database than
  :data:`filetypes.SIGNATURES`; the payload says which signals it had, so a miss
  is visible as a miss rather than as an absence.
- :func:`additional_details` is the read the hosted portal fills in
  asynchronously: the overlay (the bytes past the last section), the Rich-header
  summary, the debug entries, the directory presence flags, the section table's
  shape and the Authenticode summary.

Each read composes stored scans and reports the sources it used.  A binary whose
scans are missing is not an error: the payload carries ``sources`` naming what
was missing and the command that fills it in, and :func:`status` answers the
same question on its own, which is what the hosted ``/status`` route is for.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from reportal import store

# The scans each read composes, in the order they are reported.
DIE_SOURCES = ("pe-info", "filetype", "fingerprint")
DETAIL_SOURCES = ("pe-info", "filetype")

# The command that produces each scan, for the hint a missing source carries.
SOURCE_COMMANDS = {
    "pe-info": "reportal pe-info",
    "filetype": "reportal filetype",
    "fingerprint": "reportal enrich",
}

# Section names DIE-style output reports as a packer hint when the section table
# is the only signal available.
_PACKER_SECTION_HINTS = ("upx", "aspack", "mpress", "petite", "fsg", ".packed")


def stored_scan(conn: sqlite3.Connection, binary_id: int, kind: str) -> dict[str, Any] | None:
    """The binary's latest stored scan of *kind*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, kind)


def source_present(conn: sqlite3.Connection, binary_id: int, kind: str) -> bool:
    """Whether one source is stored.

    Every source but the fingerprint is a scan; the fingerprint lives in its own
    table, so it is read through the store's accessor rather than through the
    scan reader.
    """
    if kind == "fingerprint":
        return store.get_fingerprint(conn, binary_id) is not None
    return stored_scan(conn, binary_id, kind) is not None


def source_report(
    conn: sqlite3.Connection, binary_id: int, kinds: tuple[str, ...]
) -> dict[str, Any]:
    """Report each source's presence, with the command that produces it."""
    return {
        kind: {
            "present": source_present(conn, binary_id, kind),
            "command": SOURCE_COMMANDS.get(kind, ""),
        }
        for kind in kinds
    }


def _overlay(conn: sqlite3.Connection, binary_id: int, pe_info: dict[str, Any]) -> dict[str, Any]:
    """The bytes past the last section, from the stored size and section table."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        return {"present": False, "bytes": 0, "offset": None}
    path = Path(str(binary["path"]))
    size = path.stat().st_size if path.is_file() else int(binary["size"] or 0)
    end = 0
    for section in pe_info.get("sections") or []:
        if not isinstance(section, dict):
            continue
        raw_offset = int(section.get("raw_offset") or 0)
        raw_size = int(section.get("raw_size") or 0)
        end = max(end, raw_offset + raw_size)
    overhead = int(pe_info.get("size") or 0) - end
    return {
        "present": size > end > 0,
        "bytes": max(size - end, 0),
        "offset": end or None,
        "headers_and_padding": max(overhead, 0),
    }


def _rich_header(pe_info: dict[str, Any]) -> dict[str, Any]:
    """The Rich header's summary: its presence, entry count and build ids."""
    rich = pe_info.get("rich_header") or {}
    entries = [entry for entry in (rich.get("entries") or []) if isinstance(entry, dict)]
    builds = sorted({int(entry.get("build_id") or 0) for entry in entries})
    return {
        "present": bool(rich.get("present")),
        "entries": len(entries),
        "build_ids": builds,
        "tool_ids": sorted({int(entry.get("id") or 0) for entry in entries}),
    }


def _sections(pe_info: dict[str, Any]) -> dict[str, Any]:
    """The section table's shape: counts, the executable and writable rows."""
    sections = [row for row in (pe_info.get("sections") or []) if isinstance(row, dict)]
    return {
        "count": len(sections),
        "names": [str(row.get("name") or "") for row in sections],
        "executable": [str(row.get("name") or "") for row in sections if row.get("execute")],
        "writable": [str(row.get("name") or "") for row in sections if row.get("write")],
        "virtual_size": sum(int(row.get("virtual_size") or 0) for row in sections),
        "raw_size": sum(int(row.get("raw_size") or 0) for row in sections),
    }


def _debug_entries(pe_info: dict[str, Any]) -> list[dict[str, Any]]:
    """The debug directory's entries, each entry as the engine reported it."""
    return [entry for entry in (pe_info.get("debug") or []) if isinstance(entry, dict)]


def additional_details(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The details the hosted portal fills in asynchronously, from stored scans.

    ``sources`` names every input and whether it was present, so a caller can
    tell "the binary has no overlay" from "nothing looked for one yet".
    """
    pe_info = stored_scan(conn, binary_id, store.SCAN_KIND_PE_INFO) or {}
    presence = pe_info.get("presence") or {}
    counts = pe_info.get("counts") or {}
    sources = source_report(conn, binary_id, DETAIL_SOURCES)
    return {
        "binary_id": binary_id,
        "available": bool(pe_info),
        "format": pe_info.get("format"),
        "arch": pe_info.get("arch"),
        "bits": pe_info.get("bits"),
        "timestamp": pe_info.get("timestamp"),
        "timestamp_iso": pe_info.get("timestamp_iso"),
        "checksum": pe_info.get("checksum"),
        "size": pe_info.get("size"),
        "overlay": _overlay(conn, binary_id, pe_info),
        "rich_header": _rich_header(pe_info),
        "sections": _sections(pe_info),
        "debug": _debug_entries(pe_info),
        "presence": {
            "resources": bool(presence.get("resources")),
            "relocations": bool(presence.get("relocations")),
            "exports": bool(presence.get("exports")),
            "imports": bool(presence.get("imports")),
            "tls_directory": bool(presence.get("tls_directory")),
            "load_config": bool(presence.get("load_config")),
        },
        "counts": {
            "imports": int(counts.get("imports") or 0),
            "import_dlls": int(counts.get("import_dlls") or 0),
            "exports": int(counts.get("exports") or 0),
            "relocations": int(counts.get("relocations") or 0),
        },
        "authenticode": pe_info.get("authenticode") or {"present": False},
        "packer_section_hint": [
            name
            for name in _sections(pe_info)["names"]
            if any(hint in name.lower() for hint in _PACKER_SECTION_HINTS)
        ],
        "sources": sources,
    }


def _entropy(fingerprint: dict[str, Any] | None) -> dict[str, Any]:
    """The section entropy the fingerprint carries, or an empty summary."""
    entropies = []
    for entry in (fingerprint or {}).get("section_entropies") or []:
        if isinstance(entry, dict):
            entropies.append(entry)
    return {"sections": entropies, "packed": bool((fingerprint or {}).get("packed"))}


def _identity(pe_info: dict[str, Any], filetype: dict[str, Any]) -> dict[str, Any]:
    """The file's own identity, preferring the PE scan and falling back."""
    return {
        "format": pe_info.get("format") or filetype.get("format"),
        "arch": pe_info.get("arch") or filetype.get("arch"),
        "bits": pe_info.get("bits"),
        "mode": pe_info.get("subsystem"),
        "entry_point": pe_info.get("entry_point"),
        "image_base": pe_info.get("image_base"),
        "size": pe_info.get("size"),
    }


def die_info(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The Detect-It-Easy shaped identity, composed from the stored scans.

    Each category lists what was found and what matched it, so the answer is
    auditable: an empty ``packer`` list beside a present ``filetype`` source
    means the signature table found no packer, not that nothing ran.
    """
    pe_info = stored_scan(conn, binary_id, store.SCAN_KIND_PE_INFO) or {}
    filetype = stored_scan(conn, binary_id, store.SCAN_KIND_FILETYPE) or {}
    fingerprint = store.get_fingerprint(conn, binary_id)
    matches = [row for row in (filetype.get("matches") or []) if isinstance(row, dict)]
    by_category: dict[str, list[dict[str, Any]]] = {}
    for match in matches:
        category = str(match.get("category") or "unknown")
        by_category.setdefault(category, []).append(
            {
                "name": match.get("name"),
                "confidence": match.get("confidence"),
                "signals": match.get("signals") or [],
            }
        )
    sources = source_report(conn, binary_id, DIE_SOURCES)
    sections = _sections(pe_info)
    return {
        "binary_id": binary_id,
        "available": bool(pe_info or filetype),
        "identity": _identity(pe_info, filetype),
        "file_type": filetype.get("file_type") or pe_info.get("format"),
        "packer": by_category.get("packer", []),
        "protector": by_category.get("protector", []),
        "installer": by_category.get("installer", []),
        "runtime": by_category.get("runtime", []),
        "toolchain": by_category.get("toolchain", []),
        "by_category": filetype.get("by_category") or {},
        "entropy": _entropy(fingerprint),
        "sections": sections,
        "packer_section_hint": [
            name
            for name in sections["names"]
            if any(hint in name.lower() for hint in _PACKER_SECTION_HINTS)
        ],
        "notes": filetype.get("notes") or [],
        "sources": sources,
    }


def status(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Whether the reads above have their inputs, and what fills a gap."""
    sources = source_report(conn, binary_id, DIE_SOURCES)
    missing = [kind for kind, row in sources.items() if not row["present"]]
    return {
        "binary_id": binary_id,
        "status": "ready" if not missing else "incomplete",
        "missing": missing,
        "hint": (
            ""
            if not missing
            else "; ".join(f"{SOURCE_COMMANDS[kind]} {binary_id}" for kind in missing)
        ),
        "sources": sources,
    }

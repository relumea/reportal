"""Rebrew projects into the portal: import an existing one, or generate one.

``import_project`` reads a rebrew workspace's ``coverage.db`` and registers its
targets, functions and import stubs (``reportal import-rebrew``).
``analyse_binary`` is what an upload runs through the job queue: the engine
onboards the stored binary into a project under the workspace's ``projects/``
directory (function discovery, the coverage database), and the import then
attaches that project to the binary's row, so disassembly, decompilation and
the per-function panels have functions to read.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import rebrew.c_parser
import rebrew.workspace

from reportal import engines, lineage, store, symbol_library
from reportal._paths import db_path, projects_dir

# Engine label recorded on analyses produced by `import-rebrew`; it is what
# makes a re-import find and refresh its own analysis instead of adding one.
IMPORT_ENGINE = "rebrew-import"

# Characters a rebrew target name may carry; anything else in a binary's display
# name becomes an underscore.
_TARGET_UNSAFE = re.compile(r"[^A-Za-z0-9_]")

# Status, name source and size of a function row ingested from the engine's
# import-stub list.  An import thunk is `jmp dword ptr [iat]`, six bytes, and
# the size is what lets the disassembly route list the stub.
THUNK_STATUS = "THUNK"
THUNK_NAME_SOURCE = store.IMPORTED_NAME_SOURCE
THUNK_SIZE = 6

# An MSVC-decorated C symbol: ``_name`` (cdecl), ``_name@N`` (stdcall) or
# ``@name@N`` (fastcall).  C++ mangling is not undecorated here.
_DECORATED_SYMBOL = re.compile(r"\A[_@](?P<name>[A-Za-z_]\w*?)(?:@\d+)?\Z")


class RebrewImportError(Exception):
    """A rebrew workspace that cannot be imported."""


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of *table*."""
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _resolve_rebrew_db(project_dir: Path) -> Path:
    """Locate the coverage.db of a rebrew workspace.

    Honours ``[project] db_dir`` in the workspace's ``rebrew-project.toml``,
    falling back to ``db/coverage.db``.  The shared resolver names the path
    whether or not it exists, so the missing-file check stays here.
    """
    db_file = rebrew.workspace.db_path(project_dir)
    if not db_file.is_file():
        raise RebrewImportError(f"no coverage.db at {db_file}")
    return db_file


def _target_binaries(project_dir: Path) -> dict[str, Path]:
    """Map target id to its binary path from the workspace config.

    A target whose binary is unset, empty or absent from disk is skipped.
    """
    binaries: dict[str, Path] = {}
    config = rebrew.workspace.read_config(project_dir)
    for target_id, entry in rebrew.workspace.targets_table(config).items():
        candidate = rebrew.workspace.target_binary(project_dir, entry)
        if candidate is not None and candidate.is_file():
            binaries[target_id] = candidate
    return binaries


def _target_facts(project_dir: Path) -> dict[str, tuple[str, str]]:
    """Map target id to the ``(arch, format)`` its config names (``x86_32``, ``pe``, ...)."""
    config = rebrew.workspace.read_config(project_dir)
    return {
        target_id: (str(entry.get("arch") or ""), str(entry.get("format") or ""))
        for target_id, entry in rebrew.workspace.targets_table(config).items()
    }


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint_best_effort(
    conn: sqlite3.Connection, binary_id: int, binary_path: Path | None
) -> None:
    """Store a fingerprint for an imported binary when the engine can produce one.

    The engine never gates an import: an engine that is not importable, a
    missing binary or a failed invocation is skipped without touching the
    import result.
    """
    if binary_path is None:
        return
    engine = engines.get_engine()
    if not engine.available():
        return
    try:
        fingerprint = engine.fingerprint(binary_path)
    except engines.EngineError:
        return
    store.set_fingerprint(conn, binary_id, fingerprint)


def _stub_va(raw: Any) -> int | None:
    """Return a stub's VA as an int: a hex string from the engine, or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw), 16)
    except (TypeError, ValueError):
        return None


def _ingest_import_stubs(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    binary_path: Path | None,
    project_dir: Path,
) -> int:
    """Add the engine's import stubs as THUNK functions; returns the count added.

    Best effort: an engine that is not importable, a missing binary file or a
    failed invocation is skipped, so an import succeeds without engine data.  A
    VA the coverage-db rows already occupy is left alone, and a stub whose VA
    does not parse is skipped without aborting the rest.
    """
    if binary_path is None:
        return 0
    engine = engines.get_engine()
    if not engine.available():
        return 0
    try:
        result = engine.imports(binary_path)
    except engines.EngineError:
        return 0
    stubs = result.get("stubs")
    stubs = stubs if isinstance(stubs, list) else []
    added = 0
    for stub in stubs:
        if not isinstance(stub, dict):
            continue
        va = _stub_va(stub.get("va"))
        if va is None:
            continue
        created = store.add_function_if_absent(
            conn,
            analysis_id=analysis_id,
            va=va,
            name=str(stub.get("name") or ""),
            size=THUNK_SIZE,
            status=THUNK_STATUS,
            name_source=THUNK_NAME_SOURCE,
            source_path=str(project_dir),
        )
        if created is not None:
            added += 1
    return added


def function_name(raw: str, *, symbol: str = "", va: int) -> str:
    """The function name a coverage.db row stands for.

    *raw* is the row's name, which an older engine filled from prototype text:
    a bare declaration word (``__declspec``, ``__stdcall``, ``static``) or the
    whole prototype.  A prototype is parsed with the engine's own C parser for
    its declarator; a bare word falls back to the undecorated *symbol*
    (``_ResizeEditControl@8`` is ``ResizeEditControl``), then to the
    ``sub_<va>`` placeholder the cells import also uses.
    """
    candidate = raw.strip()
    if lineage.is_function_name(candidate):
        return candidate
    if "(" in candidate:
        parsed = rebrew.c_parser.extract_function_name_from_line(candidate)
        if parsed is not None and lineage.is_function_name(parsed[0]):
            return parsed[0]
    decorated = _DECORATED_SYMBOL.match(symbol.strip())
    if decorated is not None and lineage.is_function_name(decorated["name"]):
        return decorated["name"]
    return f"sub_{va:x}"


def _rebrew_targets(conn: sqlite3.Connection, table: str) -> list[str]:
    """Distinct targets in *table*, without the metadata table's schema row."""
    sql = f"SELECT DISTINCT target FROM {table}"
    params: tuple[str, ...] = ()
    if table == "metadata":
        sql += " WHERE target != ?"
        params = (rebrew.workspace.SCHEMA_TARGET,)
    rows = conn.execute(sql, params).fetchall()
    return sorted(str(row[0]) for row in rows)


def _functions_from_table(conn: sqlite3.Connection, target: str) -> list[dict[str, Any]]:
    """Read a target's function rows from rebrew's ``functions`` table."""
    columns = _table_columns(conn, "functions")
    if "va" not in columns:
        raise RebrewImportError("coverage.db functions table has no va column")
    wanted = ["va"] + [c for c in ("name", "size", "status", "symbol") if c in columns]
    sql = f"SELECT {', '.join(wanted)} FROM functions WHERE target = ?"
    if "markerType" in columns:
        sql += " AND markerType NOT IN ('GLOBAL', 'DATA')"
    sql += " ORDER BY va"
    functions: list[dict[str, Any]] = []
    for row in conn.execute(sql, (target,)).fetchall():
        keys = row.keys()
        va = int(row["va"])
        functions.append(
            {
                "va": va,
                "name": function_name(
                    str(row["name"] or "") if "name" in keys else "",
                    symbol=str(row["symbol"] or "") if "symbol" in keys else "",
                    va=va,
                ),
                "size": int(row["size"] or 0) if "size" in keys else 0,
                "status": str(row["status"] or "unknown") if "status" in keys else "unknown",
            }
        )
    return functions


def _functions_from_cells(conn: sqlite3.Connection, target: str) -> list[dict[str, Any]]:
    """Synthesize function rows from rebrew's ``cells`` table.

    Used when a coverage.db has no ``functions`` table: each non-empty cell
    becomes one function at the cell start, named from the cell's function
    list when present.
    """
    columns = _table_columns(conn, "cells")
    if not {"start", "state"} <= columns:
        raise RebrewImportError("coverage.db cells table has no start/state columns")
    has_end = "end" in columns
    has_functions = "functions" in columns
    selected = ", ".join(
        ["start", "state"] + (["end"] if has_end else []) + (["functions"] if has_functions else [])
    )
    functions: list[dict[str, Any]] = []
    for row in conn.execute(
        f"SELECT {selected} FROM cells WHERE target = ? AND state != 'none' ORDER BY start",
        (target,),
    ).fetchall():
        va = int(row["start"])
        end = int(row["end"]) if has_end and row["end"] is not None else va + 1
        name = ""
        if has_functions and row["functions"]:
            try:
                names = json.loads(row["functions"])
            except (json.JSONDecodeError, TypeError):
                names = []
            if isinstance(names, list) and names and isinstance(names[0], str):
                name = names[0]
        functions.append(
            {
                "va": va,
                "name": function_name(name, va=va),
                "size": max(1, end - va),
                "status": str(row["state"]).upper(),
            }
        )
    return functions


def _collect_rebrew_functions(
    conn: sqlite3.Connection, target: str, source: str
) -> list[dict[str, Any]]:
    if source == "functions":
        return _functions_from_table(conn, target)
    if source == "cells":
        return _functions_from_cells(conn, target)
    return []


def _function_source(conn: sqlite3.Connection, rebrew_db: Path) -> str:
    """The table a coverage.db's functions are read from.

    Raises :class:`RebrewImportError` for a schema with none of them.
    """
    tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    source = next((t for t in ("functions", "cells", "metadata") if t in tables), None)
    if source is None:
        raise RebrewImportError(
            f"unrecognized coverage.db schema at {rebrew_db} "
            "(no functions, cells or metadata table)"
        )
    return source


def coverage_functions(rebrew_db: Path, target: str) -> list[dict[str, Any]]:
    """One target's function rows from a coverage.db, in VA order.

    Each row is ``{"va", "name", "size", "status"}`` with the name read through
    :func:`function_name`, exactly as :func:`import_project` stores it.  Raises
    :class:`RebrewImportError` for an unrecognized schema.
    """
    with contextlib.closing(
        sqlite3.connect(rebrew.workspace.sqlite_ro_uri(rebrew_db), uri=True)
    ) as coverage:
        coverage.row_factory = sqlite3.Row
        return _collect_rebrew_functions(coverage, target, _function_source(coverage, rebrew_db))


def import_project(project_dir: Path, *, into_binary_id: int | None = None) -> dict[str, Any]:
    """Ingest a rebrew workspace into the portal database; returns a summary.

    Idempotent: a binary is identified by content hash (or name+path when the
    binary is absent), its import analysis is reused, and functions are
    upserted by VA, so a second run refreshes rows instead of duplicating.
    Each binary records the resolved project directory as its rebrew context,
    which disassembly reads back; storing it is not engine-gated.  The target
    binary's import stubs are ingested on top, best effort, as already-named
    THUNK rows that never replace a coverage-db row.
    With *into_binary_id* every target attaches to that existing row instead:
    a generated project is that binary's own, so a row deleted while it was
    being analysed stays deleted rather than being registered again.
    Raises :class:`RebrewImportError` for a missing or unrecognized workspace,
    or an *into_binary_id* that no longer exists.
    """
    project_dir = project_dir.expanduser().resolve()
    rebrew_db = _resolve_rebrew_db(project_dir)
    binaries_map = _target_binaries(project_dir)
    facts = _target_facts(project_dir)

    portal_db = db_path()
    store.init_db(portal_db)
    summary: dict[str, Any] = {
        "project": str(project_dir),
        "coverage_db": str(rebrew_db),
        "targets": [],
        "created_functions": 0,
        "updated_functions": 0,
        "stubs": 0,
    }

    with contextlib.closing(
        sqlite3.connect(rebrew.workspace.sqlite_ro_uri(rebrew_db), uri=True)
    ) as coverage:
        coverage.row_factory = sqlite3.Row
        source = _function_source(coverage, rebrew_db)
        targets = _rebrew_targets(coverage, source)
        if not targets:
            raise RebrewImportError(f"{rebrew_db} contains no targets")

        with contextlib.closing(store.connect(portal_db)) as portal:
            for target in targets:
                functions = _collect_rebrew_functions(coverage, target, source)
                binary_path = binaries_map.get(target)
                sha256 = sha256_file(binary_path) if binary_path else None
                if into_binary_id is not None:
                    if store.get_binary(portal, into_binary_id) is None:
                        raise RebrewImportError(
                            f"binary {into_binary_id} was deleted while it was analysed"
                        )
                    binary_id = into_binary_id
                else:
                    binary_id = store.add_binary(
                        portal,
                        sha256=sha256,
                        name=target,
                        path=str(binary_path) if binary_path else "",
                        size=binary_path.stat().st_size if binary_path else 0,
                        fmt=binary_path.suffix.lstrip(".").upper() if binary_path else "",
                    )
                store.set_rebrew_context(portal, binary_id, str(project_dir))
                arch, fmt = facts.get(target, ("", ""))
                store.set_binary_detected(portal, binary_id, arch=arch, fmt=fmt)
                _fingerprint_best_effort(portal, binary_id, binary_path)
                analysis = store.find_analysis(portal, binary_id=binary_id, engine=IMPORT_ENGINE)
                if analysis is None:
                    analysis_id = store.create_analysis(
                        portal,
                        binary_id=binary_id,
                        engine=IMPORT_ENGINE,
                        status="done",
                        log=f"imported from {rebrew_db}",
                    )
                else:
                    analysis_id = int(analysis["id"])
                    store.update_analysis_status(
                        portal, analysis_id, status="done", log=f"imported from {rebrew_db}"
                    )

                created = updated = 0
                for function in functions:
                    status = function["status"]
                    confidence = 1.0 if status.upper() in store.MATCHED_STATUSES else 0.0
                    _, was_created = store.upsert_function(
                        portal,
                        analysis_id=analysis_id,
                        va=function["va"],
                        name=function["name"],
                        size=function["size"],
                        status=status,
                        name_source="rebrew",
                        confidence=confidence,
                        source_path=str(project_dir),
                    )
                    if was_created:
                        created += 1
                    else:
                        updated += 1

                stubs = _ingest_import_stubs(
                    portal,
                    analysis_id=analysis_id,
                    binary_path=binary_path,
                    project_dir=project_dir,
                )

                # The functions just landed, so the local library resolve can
                # rename them now; it never fetches and never fails the import.
                symbol_library.auto_resolve(portal, binary_id)

                summary["targets"].append(
                    {
                        "name": target,
                        "binary_id": binary_id,
                        "analysis_id": analysis_id,
                        "sha256": sha256,
                        "functions": len(functions),
                        "created": created,
                        "updated": updated,
                        "stubs": stubs,
                        "arch": arch,
                        "format": fmt,
                    }
                )
                summary["created_functions"] += created
                summary["updated_functions"] += updated
                summary["stubs"] += stubs

    return summary


def target_name(display_name: str) -> str:
    """The rebrew target name for a binary called *display_name*.

    The stem with every character a target may not carry replaced, prefixed
    when it would start with a digit, so ``2k-calc.exe`` is ``t_2k_calc``.
    """
    stem = _TARGET_UNSAFE.sub("_", Path(display_name).stem).strip("_") or "target"
    return f"t_{stem}" if stem[0].isdigit() else stem


def analyse_binary(binary_id: int) -> dict[str, Any]:
    """Generate a rebrew project for a stored binary and import it.

    The project lives at ``projects/<sha256>`` in the workspace, so a second
    run re-discovers into the same directory and the import refreshes the same
    analysis instead of adding one.  Returns the import summary plus the
    engine's own onboarding report under ``intake``.  Raises
    :class:`RebrewImportError` for a binary that is unknown or has no stored
    file, and :class:`engines.EngineError` when the engine cannot onboard it.
    """
    with contextlib.closing(store.connect(db_path())) as conn:
        binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise RebrewImportError(f"no binary with id {binary_id}")
    path = Path(str(binary["path"] or ""))
    if not path.is_file():
        raise RebrewImportError(f"binary {binary_id} has no stored file to analyse")
    project = projects_dir() / str(binary["sha256"] or binary_id)
    intake = engines.get_engine().intake(path, project, target=target_name(binary["name"]))
    summary = import_project(project, into_binary_id=binary_id)
    summary["intake"] = intake
    return summary

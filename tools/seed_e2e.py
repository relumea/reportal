"""seed_e2e.py: build the workspace the Playwright suite drives.

Reuses the SPA smoke's seeding (``tools/smoke_spa.py``) so the browser suite
runs against the same real rows: a binary pointing at the sibling
``notepad-rebrew`` project with its rebrew context, an analysis with functions
read from the project's function list, a stored match pair with both
decompilations, the stored scans (PE metadata, file type, structs,
function triage, threat, remediation, security, detect, unstrip), analyst
comments, a
conversation, a knowledge document, a built graph, an auto run and a journal
entry.  It then adds the two collections the smoke leaves out, so the
Collections view and the Search view's collection table render rows instead of
their empty states.

The workspace is written under the repo's gitignored ``.scratch/`` (never
``/tmp``) and rebuilt on every run.  One JSON object carrying the seeded ids,
the collection names and the tag the smoke applies to the binary is printed to
stdout for the Playwright global setup.

Usage::

    uv run --python .venv/bin/python tools/seed_e2e.py
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path

_REPO_ROOT = next(
    candidate
    for candidate in (Path(__file__).resolve().parent, *Path(__file__).resolve().parent.parents)
    if (candidate / "pyproject.toml").is_file()
)
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from reportal import auth, data_types, store  # noqa: E402
from tools import smoke_spa  # noqa: E402

WORKSPACE_RELATIVE = Path(".scratch") / "e2e-web"

# A second binary with a list long enough to window.  The Functions table
# renders the visible rows only, and the spec that covers it needs a list where
# that matters: at 5,000 rows, rendering every one would put ~80,000 nodes in
# the DOM and take seconds.
LARGE_BINARY_NAME = "wide.exe"
LARGE_FUNCTIONS = 5000

# The team the seeded binaries can be scoped to.  It gives the upload panel's
# scope select a real choice and the scope route something to set, so the suite
# covers registering a file into a team rather than only into the workspace.
TEAM_NAME = "e2e scope team"

# Collections seeded so the Collections view and the Search view's collection
# table list rows.  The first carries the seeded binary, the second stays empty
# so the member count column renders both a number and a zero.
COLLECTIONS: tuple[tuple[str, str], ...] = (
    ("Notepad workspace", "Binaries the notepad import came from"),
    ("Windows samples", "GUI utilities kept for codegen comparison"),
)

# Data types seeded so the Data types panel renders its list, its kind filter,
# its namespace tree and its counts.  Members carry only what the model needs
# (name, type, pointer, array count); `data_types.recompute` derives the
# offsets and the size from the kind.  Two kinds and two namespace groups give
# the Playwright specs something to filter by.
TYPES: tuple[dict[str, object], ...] = (
    {
        "name": "NP_HEADER",
        "kind": data_types.KIND_STRUCT,
        "members": (
            {"name": "magic", "type": "unsigned short", "pointer": False, "count": None},
            {"name": "flags", "type": "unsigned int", "pointer": False, "count": None},
            {"name": "name", "type": "char", "pointer": False, "count": 32},
        ),
        "source": "scan",
    },
    {
        "name": "NP_ENTRY",
        "kind": data_types.KIND_STRUCT,
        "members": (
            {"name": "va", "type": "unsigned int", "pointer": False, "count": None},
            {"name": "next", "type": "NP_ENTRY", "pointer": True, "count": None},
        ),
        "source": "manual",
    },
    {
        "name": "NP_FLAGS",
        "kind": data_types.KIND_ENUM,
        "values": ({"name": "NP_FLAG_A", "value": 0}, {"name": "NP_FLAG_B", "value": 1}),
        "source": "scan",
    },
    {
        "name": "NP_BLOCK",
        "kind": data_types.KIND_UNION,
        "members": (
            {"name": "as_int", "type": "unsigned int", "pointer": False, "count": None},
            {"name": "as_bytes", "type": "unsigned char", "pointer": False, "count": 4},
        ),
        "source": "manual",
    },
    {
        "name": "WIN_DWORD",
        "kind": data_types.KIND_TYPEDEF,
        "namespace": "winnt",
        "target": "unsigned int",
        "source": "manual",
    },
    {
        "name": "WIN_HANDLE",
        "kind": data_types.KIND_POINTER,
        "namespace": "winnt",
        "target": "void",
        "source": "manual",
    },
    {
        "name": "WIN_KERNEL_MUTEX",
        "kind": data_types.KIND_STRUCT,
        "namespace": "winnt::kernel",
        "members": ({"name": "owner", "type": "unsigned int", "pointer": False, "count": None},),
        "source": "manual",
    },
)


def seed(workspace: Path) -> dict[str, object]:
    """Build *workspace* and return the ids and collections the suite needs."""
    project_dir = smoke_spa.sibling(smoke_spa.NOTEPAD_PROJECT_RELATIVE)
    binary_path = project_dir / "original" / "notepad.exe"
    functions_file = smoke_spa.function_seed_file(project_dir)
    rebrew_bin = smoke_spa.sibling(smoke_spa.REBREW_RELATIVE)
    for required in (binary_path, functions_file, rebrew_bin):
        if not required.is_file():
            raise SystemExit(f"missing prerequisite: {required}")

    ids = smoke_spa.build_workspace(workspace, project_dir, binary_path, functions_file)
    function_name = smoke_spa.read_functions(functions_file, 1)[0][1]
    collections: list[dict[str, object]] = []
    with contextlib.closing(store.connect(workspace / "reportal.db")) as conn:
        for index, (name, description) in enumerate(COLLECTIONS):
            collection_id = store.create_collection(
                conn, name=name, description=description, scope="binary"
            )
            if index == 0:
                store.add_collection_binary(conn, collection_id, ids["binary_id"])
            collections.append({"id": collection_id, "name": name})
        for entry in TYPES:
            kind = str(entry["kind"])
            members = entry.get("members", ())
            normalized, size = data_types.recompute(
                kind,
                members,
                str(entry.get("target") or ""),
                entry.get("element_count"),
            )
            store.add_data_type(
                conn,
                binary_id=int(ids["binary_id"]),
                name=str(entry["name"]),
                size=size,
                members=normalized,
                kind=kind,
                namespace=str(entry.get("namespace") or ""),
                values=entry.get("values", ()),
                target=str(entry.get("target") or ""),
                element_count=entry.get("element_count"),
                source=str(entry["source"]),
            )
        # Every stored type name, not just the ones seeded here: the workspace
        # builder stores its own, and the panel lists all of them.
        stored_types = [row["name"] for row in store.list_data_types(conn, int(ids["binary_id"]))]
        large_binary_id = _seed_large_binary(conn)
        stale_run = _seed_stale_run(conn, large_binary_id)
        team = auth.create_team(conn, name=TEAM_NAME)
    return {
        "workspace": str(workspace),
        "ids": ids,
        "function_name": function_name,
        "collections": collections,
        "types": stored_types,
        "tag_name": smoke_spa.TAG_NAME,
        "large_binary_id": large_binary_id,
        "large_function_count": LARGE_FUNCTIONS,
        "stale_run": stale_run,
        "team": {"id": int(team["id"]), "name": str(team["name"])},
    }


def _seed_large_binary(conn: object) -> int:
    """One binary with a long function list, for the windowed table.

    The rows are written with one ``executemany``: this is fixture data, and a
    per-row helper call would spend the seed run on commits.  Names are
    ``sub_<va>``, the placeholder shape an importer leaves, and the VA order
    matches the id order so the last row is the address the spec scrolls to.
    It is written under its own platform so the analyses spec's platform filter
    still narrows to the one seeded target.
    """
    import sqlite3

    from reportal import store as store_module

    assert isinstance(conn, sqlite3.Connection)
    binary_id = store_module.add_binary(
        conn,
        sha256="ff" * 32,
        name=LARGE_BINARY_NAME,
        size=1 << 20,
        fmt="ELF",
        arch="x86_64",
    )
    analysis_id = store_module.create_analysis(conn, binary_id=binary_id, engine="manual")
    conn.executemany(
        "INSERT INTO functions (analysis_id, va, name, size, status, name_source, confidence)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                analysis_id,
                0x1000 + index * 0x20,
                f"sub_{0x1000 + index * 0x20:x}",
                16 + index % 64,
                "STUB",
                "rebrew",
                0.5,
            )
            for index in range(LARGE_FUNCTIONS)
        ],
    )
    conn.commit()
    return binary_id


def _seed_stale_run(conn: object, binary_id: int) -> dict[str, int]:
    """A run a dead process left `running` on the large binary.

    The Auto view offers Recover only while a run reads `running`, and that is
    the state a killed process leaves behind, so the browser suite needs one to
    drive the control.  It carries a root and one pending batch, which is what
    the coordinator had planned when it died.
    """
    import sqlite3

    from reportal import auto_store

    assert isinstance(conn, sqlite3.Connection)
    run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={"worker": "offline"})
    root_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=None,
        depth=auto_store.AUTO_ROOT_DEPTH,
        kind=auto_store.AUTO_TASK_ROOT,
        title="binary",
    )
    auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=root_id,
        depth=auto_store.AUTO_BATCH_DEPTH,
        kind=auto_store.AUTO_TASK_BATCH,
        title="batch 0",
    )
    return {"binary_id": binary_id, "run_id": run_id, "tasks": 1}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(description="Seed the Playwright suite's reportal workspace.")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=_REPO_ROOT / WORKSPACE_RELATIVE,
        help=f"workspace directory (default: {WORKSPACE_RELATIVE})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Seed the workspace and print its state as one JSON object."""
    workspace = parse_args(argv).workspace.resolve()
    json.dump(seed(workspace), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

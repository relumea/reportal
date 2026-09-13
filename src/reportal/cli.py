"""Typer CLI for reportal.

Subcommands: ``init`` (write the workspace marker and database), ``serve``
(the portal web server), ``stats`` (row counts), ``revert`` (undo a rename),
``tags``/``tag`` (list tags, tag a binary), ``apply-match`` (rename to a match
candidate), ``diff`` (align a function against a match candidate), ``lineage``
(compare two binaries' functions and report what is unchanged, changed, added
or removed), ``add-binary`` (register a binary by content hash), ``download``
(write a stored binary's bytes to a path), ``enrich``
(store an engine fingerprint), ``decompile`` (decompile one function through
the engine), ``summary``/``ai-comments``/``suggest-types`` (compute and store one
AI artifact of a function's decompilation through the optional LLM bridge),
``suggest-renames``/``apply-renames``/``revert-renames`` (suggest identifier
renames for a stored decompilation, apply a subset of them with a journal and
restore the journaled text),
``xrefs`` (list a function's cross-references), ``structs`` (recover struct
definitions and store them), ``types``/``types-import``/``type-rename``/
``type-member``/``type-kind``/``type-namespace``/``type-size``/
``type-member-add``/``type-member-gap``/``type-member-ungap``/
``type-value-add``/``type-value-edit``/``type-value-remove``/``types-export``
(list, seed, edit and export the editable type model, its kind, namespace and
declared size, its member shape and position and its enum values),
``types-history``/``types-revert`` (list a type's edits and
restore the state one recorded), ``crypto-scan`` (detect crypto constants and APIs
and store the result), ``pe-info`` (inspect a binary's PE identity, sections,
security flags, signature, debug and Rich-header metadata and store the
result), ``capabilities`` (classify a binary from its imports and
strings and store the result), ``filetype`` (detect file type, packer and
protector signatures over the engine's PE sections, entropies, imports and
strings and store the result), ``secrets`` (scan a binary's strings for
credentials and high-entropy values and store the result), ``protocols``
(infer the network protocols a binary speaks from its imports and strings and
store the result), ``behavior`` (scan a
binary's execution, networking or filesystem behavior from its imports and
strings and store the result), ``hardening`` (scan a binary's anti-analysis or
obfuscation surface from its fingerprints, imports, strings and stored triage
and store the result), ``security-scan`` (scan the project's reversed C
sources for unsafe API use and store the findings), ``triage`` (store the
engine's one-shot dossier), ``function-triage`` (summarize and score a binary's
selected functions through the optional LLM bridge, falling back to a
deterministic heuristic, and store the result), ``report`` (generate the
engine's HTML report into
the workspace and store the result), ``unstrip`` (store library-identification
rename proposals) and ``unstrip-apply`` (apply one stored proposal).
``signature-history`` and ``signature-revert`` list a function's signature
edits and restore the state one recorded, ``memory`` reads a window of a
binary's bytes by address through the engine, ``memory-page`` pages the bytes
for the full-file hex view with a stated gap where the section map backs none,
``references`` lists a function's globals, callers and callees, ``strings``
lists a binary's strings sorted by value or length, and ``section-coverage``
reports per-section byte coverage over the stored functions.
``conversations`` lists the stored chats, ``chat-new`` opens one scoped to a
function or binary, and ``chat`` sends one message through the optional LLM
bridge.  ``pipeline`` runs the AI decompilation component composition over one
function and stores the run, and ``pipeline-revert`` undoes what one stored run
wrote.  ``auto`` decomposes a binary's outstanding functions into batches and
works them with a worker (a dry run by default), ``auto-recover`` closes a run a
dead process left ``running``, and ``auto-revert`` removes what one stored auto
run wrote.  ``ingest``/``ingest-url``/``documents``/
``knowledge`` store and rank knowledge documents (``ingest-url`` fetches a
URL, off by default), and ``graph-build``/``graph`` rebuild and show
the deterministic graph derived from the stored rows.  ``graph-backends``
lists the pluggable graph backends, ``graph-sync`` pushes one binary's graph
to a backend (the local store, or the optional Cognee extra) and
``graph-query`` searches a backend that supports querying.  ``families`` lists the
locally registered malware families, ``family-add`` registers one from a
reference binary, ``family-rm`` deletes one and ``detect`` matches a binary
against them.
Human output goes to stderr through Rich; ``--json`` payloads go to stdout so
they can be piped.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import webbrowser
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any, NoReturn, cast

import rebrew.workspace
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from reportal import (
    __version__,
    analysis_log,
    auth,
    auto_mode,
    auto_store,
    auto_workers,
    behavior,
    bulk_actions,
    capabilities,
    comments,
    components,
    composition,
    conversations,
    data_types,
    details,
    diffview,
    effects,
    engines,
    families,
    filetypes,
    function_triage,
    graph,
    graph_backends,
    hardening,
    instance,
    integrations,
    jobs,
    journal,
    knowledge,
    lineage,
    llm,
    matching,
    notifications,
    pdf,
    pipeline,
    protocols,
    related,
    remediation,
    remote_ingest,
    renames,
    secrets,
    signatures,
    similarity,
    store,
    threat,
    unstrip,
    zipcrypto,
)
from reportal._paths import (
    DB_NAME,
    MARKER,
    WorkspaceNotFound,
    db_path,
    project_root,
    reports_dir,
)
from reportal.surface import journaled_data_type_write as _journal_data_type_write
from reportal.surface import journaled_signature_write as _journal_signature_write

console = Console(stderr=True)

# Engine label recorded on analyses produced by `import-rebrew`; it is what
# makes a re-import find and refresh its own analysis instead of adding one.
IMPORT_ENGINE = "rebrew-import"

# Scope of the rows a binary's match run replaces: the matches its functions own.
_BINARY_MATCHES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Scope of the signature rows a binary's seed run replaces: one row per function
# of the binary, reached through its analyses.
_BINARY_SIGNATURES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Status, name source and size of a function row ingested from the engine's
# import-stub list.  An import thunk is `jmp dword ptr [iat]`, six bytes, and
# the size is what lets the disassembly route list the stub.
THUNK_STATUS = "THUNK"
THUNK_NAME_SOURCE = store.IMPORTED_NAME_SOURCE
THUNK_SIZE = 6

# Matches shown by `reportal match` in human mode; the JSON payload carries
# the same rows.  A whole-corpus run produces one row per pair, too many to
# read, so the report keeps the best.
MAX_REPORT_ROWS = 50

# Characters of a matched chunk `reportal knowledge` prints as its snippet.
MAX_SNIPPET_CHARS = 200

# String rows `reportal strings` prints in human mode; the JSON payload carries
# every row.  A real binary produces tens of thousands.
_STRING_ROWS_SHOWN = 200

# IOC values `reportal threat` prints per category in human mode; the JSON
# payload carries every finding.
_IOC_SAMPLE_SHOWN = 3

# Fingerprint fields shown by `enrich` in human mode, in reading order.
_FINGERPRINT_FIELDS: tuple[str, ...] = (
    "md5",
    "sha1",
    "sha256",
    "crc32",
    "format",
    "arch",
    "size",
    "imphash",
)

# Dossier `meta` fields shown by `triage` in human mode, in reading order.
_TRIAGE_META_FIELDS: tuple[str, ...] = ("format", "image_base", "text_va", "text_size")

# Dossier meta fields rendered as hex: a decimal VA is unreadable.
_TRIAGE_HEX_FIELDS = frozenset({"image_base", "text_va"})

# Dossier sections `triage` counts in human mode, in reading order.
_TRIAGE_COUNT_SECTIONS: tuple[str, ...] = ("strings", "imports", "references", "functions")

# Coverage-summary fields `report` shows in human mode, in reading order.
_REPORT_SUMMARY_FIELDS: tuple[str, ...] = (
    "total_functions",
    "covered_functions",
    "coverage_pct",
    "matched_pct",
    "byte_coverage_pct",
)

# Human label per AI artifact kind, shown in the header line of the AI commands.
_AI_KIND_LABELS: dict[str, str] = {
    llm.AI_KIND_SUMMARY: "summary",
    llm.AI_KIND_COMMENTS: "inline comments",
    llm.AI_KIND_TYPES: "type suggestions",
}

_MARKER_TEMPLATE = """\
# reportal workspace marker.  The directory containing this file is the
# portal root; reportal.db beside it holds all portal state.
[portal]
db = "reportal.db"
"""

app = typer.Typer(
    help="Self-hosted reverse-engineering portal over rebrew, resembl and recoverage.",
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reportal {__version__}")
        raise typer.Exit


@app.callback()
def _app_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


def _fail(message: str, json_output: bool) -> NoReturn:
    """Report a command failure in human or JSON form, then exit 1.

    The human form escapes *message*: it can carry a path or a config table
    name, and Rich would otherwise read a bracket as markup and drop it.
    """
    if json_output:
        typer.echo(json.dumps({"error": message}))
    else:
        console.print(f"[red]{escape(message)}[/red]")
    raise typer.Exit(1)


def _db_path(json_output: bool) -> Path:
    """Return the workspace database path, failing through :func:`_fail` outside one.

    Only ``init`` resolves its target directly; every other command needs an
    existing workspace, so a missing marker is a command failure rather than a
    traceback.
    """
    try:
        return db_path()
    except WorkspaceNotFound as exc:
        _fail(str(exc), json_output)


def _print_journal_action(log: journal.Journal, json_output: bool) -> None:
    """Report the action id a wired command recorded.

    The line goes to stderr in human mode; a ``--json`` payload carries the
    same id in its ``journal_action`` field, so stdout stays machine-readable.
    """
    if json_output or not log.recorded():
        return
    console.print(f"[dim]journal action {log.action}[/dim]")


def _run_scan_command(
    conn: sqlite3.Connection, binary_id: int, kind: str, run: Callable[[], Any]
) -> tuple[journal.Journal, Any]:
    """Run one scan that stores itself through a journal; returns (journal, result)."""
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        result = journal.journaled_scan(conn, log, binary_id, kind, run)
    return log, result


def _write_text_atomic(path: Path, text: str) -> Path:
    """Write *text* to *path* through a same-directory temp file and rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return path


# ── init ───────────────────────────────────────────────────────────


@app.command()
def init(
    directory: Path = typer.Option(Path("."), "--dir", help="Directory to initialise"),
) -> None:
    """Create a reportal workspace (reportal.toml + reportal.db)."""
    target = directory.expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    marker = target / MARKER
    if marker.exists():
        console.print(f"[yellow]{marker} already exists, leaving it untouched.[/yellow]")
    else:
        marker.write_text(_MARKER_TEMPLATE, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {marker}")
    created = not (target / DB_NAME).exists()
    store.init_db(target / DB_NAME)
    verb = "Created" if created else "Reused"
    console.print(f"[green]{verb}[/green] {target / DB_NAME}")
    console.print("\nNext steps:")
    console.print(f"  cd {target}")
    console.print("  reportal import-rebrew <rebrew-project-dir>")
    console.print("  reportal serve")


# ── serve ──────────────────────────────────────────────────────────


def _require_lan_auth(portal_db: Path) -> None:
    """Refuse a remote bind that would expose an unauthenticated API.

    A loopback bind is the single-user default and needs no identity; a bind
    another machine can reach is a different promise, so it needs token auth
    switched on and at least one enabled user token, and exits with the way to
    get there instead of serving an open API.
    """
    if not auth.required():
        _fail(
            f"refusing to bind beyond loopback without token auth: {auth.NOT_REQUIRED_DETAIL}",
            False,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        active = [
            user for user in auth.list_users(conn) if user["has_token"] and not user["disabled"]
        ]
    if not active:
        _fail(f"refusing to bind beyond loopback: {auth.NO_USER_DETAIL}", False)


@app.command()
def serve(
    port: int = typer.Option(8002, "--port", "-p", min=0, max=65535, help="Port to serve on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind to"),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open browser automatically"),
) -> None:
    """Start the reportal web server."""
    # Importing the composition root registers every route on ``server.app``,
    # which is the application uvicorn then serves.
    import reportal.webapp  # noqa: F401
    from reportal import server as _server
    from reportal.server import LOOPBACK_HOSTS

    path = _db_path(json_output=False)
    if not path.exists():
        store.init_db(path)

    is_loopback = host in LOOPBACK_HOSTS
    if not is_loopback:
        _require_lan_auth(path)
    _server.configure_hosts(set(LOOPBACK_HOSTS) if is_loopback else None)

    display_host = f"[{host}]" if ":" in host else host
    url = f"http://{display_host}:{port}"
    console.print(f"Serving reportal at {url}")
    console.print(f"  DB: {path}")
    console.print("  Stop: Ctrl+C")

    if not no_open:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()

    try:
        _server.run(host, port)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        _fail(f"Failed to start server on {url}: {exc.strerror or exc}", json_output=False)


# ── teams ──────────────────────────────────────────────────────────


@app.command()
def teams(json_output: bool = typer.Option(False, "--json", help="Output results as JSON")) -> None:
    """List the teams with their member counts."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = auth.list_teams(conn)
    if json_output:
        typer.echo(json.dumps({"teams": rows, "count": len(rows)}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="magenta", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("Members", justify="right")
    table.add_column("Description", style="dim")
    for row in rows:
        table.add_row(
            str(row["id"]), str(row["name"]), str(row["member_count"]), row["description"]
        )
    console.print(f"\n[bold cyan]{len(rows)} team(s)[/bold cyan]")
    console.print(table)


@app.command("team-add")
def team_add(
    name: str = typer.Argument(..., help="Team name"),
    description: str = typer.Option("", "--description", help="What the team works on"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Create a team; journaled and revertible."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                team = auth.create_team(conn, name=name, description=description)
            except auth.AuthError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
            journal.journaled_create(
                log,
                table=auth.TEAM_TABLE,
                key=int(team["id"]),
                description=f"created team {team['name']}",
            )
    payload = log.attach(team)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(f"[green]Created[/green] team {team['name']} (id {team['id']})")
    _print_journal_action(log, json_output)


@app.command("team-rm")
def team_rm(
    team_id: int = typer.Argument(..., help="Team id to delete"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete a team; the objects it owned return to the whole workspace."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not yes and not typer.confirm(f"Delete team {team_id}?"):
        _fail("aborted", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if auth.get_team(conn, team_id) is None:
            _fail(f"no team with id {team_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            for table, where in (
                (auth.TEAM_TABLE, "id = ?"),
                (auth.MEMBER_TABLE, "team_id = ?"),
                ("binaries", "owner_team_id = ?"),
                ("collections", "owner_team_id = ?"),
            ):
                journal.journaled_rows(
                    conn,
                    log,
                    table=table,
                    where=where,
                    params=(team_id,),
                    description=f"deleted team {team_id} ({table})",
                )
            auth.delete_team(conn, team_id)
    payload = log.attach({"deleted": team_id})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(f"[green]Deleted[/green] team {team_id}")
    _print_journal_action(log, json_output)


@app.command("team-member")
def team_member(
    team_id: int = typer.Argument(..., help="Team id"),
    user_id: int = typer.Argument(..., help="User id to add or remove"),
    remove: bool = typer.Option(False, "--remove", help="Remove the membership instead"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add or remove one user's team membership; journaled and revertible."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if auth.get_team(conn, team_id) is None:
            _fail(f"no team with id {team_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if remove:
                changed = auth.remove_member(conn, team_id, user_id)
                if changed:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"removed user {user_id} from team {team_id}",
                        journal.row_restore_descriptor(
                            auth.MEMBER_TABLE, [{"team_id": team_id, "user_id": user_id}]
                        ),
                    )
            else:
                changed = auth.add_member(conn, team_id, user_id)
                if changed:
                    journal.journaled_create(
                        log,
                        table=auth.MEMBER_TABLE,
                        key={"team_id": team_id, "user_id": user_id},
                        description=f"added user {user_id} to team {team_id}",
                    )
            team = auth.get_team(conn, team_id)
    if not changed:
        _fail(
            f"user {user_id} is "
            + ("not in " if remove else "unknown or already in ")
            + f"team {team_id}",
            json_output,
        )
    payload = log.attach(team or {})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    verb = "Removed" if remove else "Added"
    console.print(
        f"[green]{verb}[/green] user {user_id} {'from' if remove else 'to'} team {team_id}"
    )
    _print_journal_action(log, json_output)


def _run_scope(
    portal_db: Path,
    *,
    kind: str,
    row_id: int,
    visibility: str,
    team_id: int | None,
    json_output: bool,
) -> dict[str, Any]:
    """Set one object's scope, journaled, and return the payload."""
    table = "binaries" if kind == "binary" else "collections"
    with contextlib.closing(store.connect(portal_db)) as conn:
        current = (
            store.get_binary(conn, row_id)
            if kind == "binary"
            else store.get_collection(conn, row_id)
        )
        if current is None:
            _fail(f"no {kind} with id {row_id}", json_output)
        owner, resolved = auth.scope_of(conn, team_id=team_id, visibility=visibility)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=table,
                where="id = ?",
                params=(row_id,),
                description=f"scoped {kind} {row_id} to {resolved}",
            )
            if kind == "binary":
                updated = store.set_binary_scope(
                    conn, row_id, owner_team_id=owner, visibility=resolved
                )
            else:
                updated = store.set_collection_scope(
                    conn, row_id, owner_team_id=owner, visibility=resolved
                )
    return log.attach(updated or {})


@app.command("binary-scope")
def binary_scope(
    binary_id: int = typer.Argument(..., help="Binary id"),
    visibility: str = typer.Option(auth.VISIBILITY_PUBLIC, "--visibility", help="public or team"),
    team_id: int | None = typer.Option(None, "--team", help="Owning team id for --visibility team"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Set which team owns a binary and whether the workspace may see it."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    try:
        payload = _run_scope(
            portal_db,
            kind="binary",
            row_id=binary_id,
            visibility=visibility,
            team_id=team_id,
            json_output=json_output,
        )
    except auth.AuthError as exc:
        _fail(f"{exc.code}: {exc.detail}", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[green]Scoped[/green] binary {binary_id}: {payload.get('visibility')}"
        f" (team {payload.get('owner_team_id')})"
    )


@app.command("collection-scope")
def collection_scope(
    collection_id: int = typer.Argument(..., help="Collection id"),
    visibility: str = typer.Option(auth.VISIBILITY_PUBLIC, "--visibility", help="public or team"),
    team_id: int | None = typer.Option(None, "--team", help="Owning team id for --visibility team"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Set which team owns a collection and whether the workspace may see it."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    try:
        payload = _run_scope(
            portal_db,
            kind="collection",
            row_id=collection_id,
            visibility=visibility,
            team_id=team_id,
            json_output=json_output,
        )
    except auth.AuthError as exc:
        _fail(f"{exc.code}: {exc.detail}", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[green]Scoped[/green] collection {collection_id}: {payload.get('visibility')}"
        f" (team {payload.get('owner_team_id')})"
    )


# ── users ──────────────────────────────────────────────────────────


@app.command()
def users(json_output: bool = typer.Option(False, "--json", help="Output results as JSON")) -> None:
    """List the local users with their roles and state."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = auth.list_users(conn)
    if json_output:
        typer.echo(
            json.dumps({"users": rows, "count": len(rows), "auth_required": auth.required()})
        )
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="magenta", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("Role")
    table.add_column("Token")
    table.add_column("State")
    table.add_column("Created", style="dim")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["name"]),
            str(row["role"]),
            "yes" if row["has_token"] else "no",
            "disabled" if row["disabled"] else "active",
            str(row["created_at"]),
        )
    console.print(f"\n[bold cyan]{len(rows)} user(s)[/bold cyan]")
    console.print(table)
    if not auth.required():
        console.print(
            "Token auth is off. An install that only binds loopback needs none; a remote bind"
            f" requires it: {auth.NOT_REQUIRED_DETAIL}"
        )


@app.command("user-add")
def user_add(
    name: str = typer.Argument(..., help="User name"),
    role: str = typer.Option(auth.ROLE_ANALYST, "--role", help="viewer, analyst or admin"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Create a user and print its token once.

    Only the token's digest is stored, so the token cannot be read back later;
    `reportal user-token <id>` issues a new one.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                user, token = auth.add_user(conn, name=name, role=role)
            except auth.AuthError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
            journal.journaled_create(
                log,
                table=auth.TABLE,
                key=int(user["id"]),
                description=f"created user {user['name']}",
            )
    payload = log.attach({**user, "token": token})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[green]Created[/green] user {user['name']} (id {user['id']}, role {user['role']})"
    )
    console.print(f"  token: {token}")
    console.print("  This is the only time the token is shown.")
    _print_journal_action(log, json_output)


@app.command("user-token")
def user_token(
    user_id: int = typer.Argument(..., help="User id whose token to replace"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Replace one user's token and print the new one once."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if auth.get_user(conn, user_id) is None:
            _fail(f"no user with id {user_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"rotated the token of user {user_id}",
            )
            token = auth.rotate_token(conn, user_id)
    payload = log.attach({"id": user_id, "token": token})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(f"[green]Rotated[/green] the token of user {user_id}: {token}")
    _print_journal_action(log, json_output)


@app.command("user-edit")
def user_edit(
    user_id: int = typer.Argument(..., help="User id to change"),
    role: str | None = typer.Option(None, "--role", help="New role"),
    disable: bool = typer.Option(False, "--disable", help="Disable the user's token"),
    enable: bool = typer.Option(False, "--enable", help="Re-enable the user's token"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Set a user's role, or disable or re-enable it; journaled."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if role is None and not disable and not enable:
        _fail("provide --role, --disable or --enable", json_output)
    if disable and enable:
        _fail("--disable and --enable are mutually exclusive", json_output)
    disabled = True if disable else (False if enable else None)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if auth.get_user(conn, user_id) is None:
            _fail(f"no user with id {user_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"updated user {user_id}",
            )
            try:
                updated = auth.update_user(conn, user_id, role=role, disabled=disabled)
            except auth.AuthError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
    payload = log.attach(updated or {})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if updated is not None:
        state = "disabled" if updated["disabled"] else "active"
        console.print(f"[green]Updated[/green] user {user_id}: role {updated['role']}, {state}")
    _print_journal_action(log, json_output)


@app.command("user-rm")
def user_rm(
    user_id: int = typer.Argument(..., help="User id to delete"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete one user; journaled, so a revert puts the row back."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not yes and not typer.confirm(f"Delete user {user_id}?"):
        _fail("aborted", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if auth.get_user(conn, user_id) is None:
            _fail(f"no user with id {user_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"deleted user {user_id}",
            )
            auth.delete_user(conn, user_id)
    payload = log.attach({"deleted": user_id})
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(f"[green]Deleted[/green] user {user_id}")
    _print_journal_action(log, json_output)


# ── mcp ────────────────────────────────────────────────────────────


@app.command()
def mcp(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Run the stdio MCP server for a local MCP client."""
    from reportal import mcp_server, mcp_tools

    try:
        workspace = project_root()
    except WorkspaceNotFound as exc:
        _fail(str(exc), json_output)
    store.init_db(db_path())
    console.print(
        f"[green]reportal mcp[/green] {mcp_server.SERVER_NAME} {mcp_server.SERVER_VERSION},"
        f" {len(mcp_tools.tools())} tools, workspace {workspace}"
    )
    mcp_server.run_server()


# ── stats ──────────────────────────────────────────────────────────


@app.command()
def stats(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Print portal row counts."""
    path = _db_path(json_output)
    if not path.exists():
        _fail(f"no reportal database at {path} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(path)) as conn:
        counts = store.counts(conn)
    if json_output:
        typer.echo(json.dumps({"db": str(path), **counts}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    for key, value in counts.items():
        table.add_row(key, str(value))
    console.print(f"\n[bold cyan]{path}[/bold cyan]")
    console.print(table)


# ── analyses ───────────────────────────────────────────────────────


@app.command("analysis")
def analysis_command(
    analysis_id: int = typer.Argument(..., help="Analysis id to read"),
    status: bool = typer.Option(False, "--status", help="The lifecycle read instead of the detail"),
    params: bool = typer.Option(False, "--params", help="What a re-run would need"),
    func_maps: bool = typer.Option(False, "--func-maps", help="The function map instead"),
    tags: bool = typer.Option(False, "--tags", help="Only the tags on the analysis's binary"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """One analysis: its counts, or its status, params, function map or tags."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        if status:
            payload: dict[str, Any] = store.analysis_status(conn, analysis_id) or {}
        elif params:
            payload = store.analysis_params(conn, analysis_id) or {}
        elif func_maps:
            functions = store.list_functions(conn, analysis_id=analysis_id, sort="va", order="asc")
            payload = {
                "analysis_id": analysis_id,
                "functions": [
                    {"va": int(row["va"]), "name": str(row["name"]), "size": int(row["size"] or 0)}
                    for row in functions
                ],
                "total": store.count_functions(conn, analysis_id=analysis_id),
            }
        elif tags:
            analysis = store.get_analysis(conn, analysis_id)
            binary_id = int(analysis["binary_id"]) if analysis else 0
            payload = {
                "analysis_id": analysis_id,
                "tags": [tag["name"] for tag in store.get_binary_tags(conn, binary_id)],
            }
        else:
            payload = store.analysis_detail(conn, analysis_id) or {}
    if json_output:
        typer.echo(json.dumps(payload))
        return
    for key, value in payload.items():
        if key in {"scans", "functions"} and isinstance(value, list):
            console.print(f"{key}: {len(value)}")
            continue
        console.print(f"{key}: {value}")


@app.command("analysis-update")
def analysis_update_command(
    analysis_id: int = typer.Argument(..., help="Analysis id to relabel"),
    engine: str = typer.Option(..., "--engine", help="The engine label to set"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Relabel one analysis's engine; journaled and revertible."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="analyses",
                where="id = ?",
                params=(analysis_id,),
                description=f"relabelled analysis {analysis_id}",
            )
            updated = store.update_analysis(conn, analysis_id, engine=engine) or {}
    if json_output:
        typer.echo(json.dumps(log.attach(updated)))
        return
    console.print(f"analysis {analysis_id}: engine {updated.get('engine')}")


@app.command("analysis-log")
def analysis_log_command(
    analysis_id: int = typer.Argument(..., help="Analysis id to log against"),
    message: str = typer.Argument(..., help="What to record"),
    severity: str = typer.Option(
        analysis_log.SEVERITY_INFO, "--severity", help="info, warn or error"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Append one log entry to an analysis; journaled and revertible."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if severity not in analysis_log.SEVERITIES:
        _fail(
            f"unknown severity: {severity}; expected one of {', '.join(analysis_log.SEVERITIES)}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        action = journal.new_action()
        try:
            with journal.journaled(conn, action) as log:
                entry_id = analysis_log.append_entry(
                    conn, analysis_id, message=message, severity=severity
                )
                journal.journaled_create(
                    log,
                    table=analysis_log.TABLE,
                    key=entry_id,
                    description=f"logged an entry on analysis {analysis_id}",
                )
        except ValueError as exc:
            _fail(str(exc), json_output)
    payload = {"id": entry_id, "analysis_id": analysis_id, "severity": severity, "message": message}
    if json_output:
        typer.echo(json.dumps(log.attach(payload)))
        return
    console.print(f"logged entry {entry_id} on analysis {analysis_id}")


@app.command("analysis-requeue")
def analysis_requeue_command(
    analysis_id: int = typer.Argument(..., help="Analysis id to requeue"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Put an analysis back to pending and clear its finish time; journaled."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="analyses",
                where="id = ?",
                params=(analysis_id,),
                description=f"requeued analysis {analysis_id}",
            )
            logged_before = journal.snapshot_rows(
                conn, table=analysis_log.TABLE, where="analysis_id = ?", params=(analysis_id,)
            )
            updated = store.requeue_analysis(conn, analysis_id) or {}
            journal.journaled_new_rows(
                conn,
                log,
                table=analysis_log.TABLE,
                where="analysis_id = ?",
                params=(analysis_id,),
                before=logged_before,
                key=["id"],
                description=f"logged the requeue of analysis {analysis_id}",
            )
    if json_output:
        typer.echo(json.dumps(log.attach(updated)))
        return
    console.print(f"analysis {analysis_id}: {updated.get('status')}")


@app.command("analysis-tags")
def analysis_tags_command(
    analysis_id: int = typer.Argument(..., help="Analysis id whose binary's tags to set"),
    names: list[str] = typer.Argument(..., help="The tags the binary should carry"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Replace the tags on the analysis's binary, the scope reportal tags at."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        binary_id = int(analysis["binary_id"])
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            current = {
                str(tag["name"]): int(tag["id"]) for tag in store.get_binary_tags(conn, binary_id)
            }
            for name in sorted(set(names) - set(current)):
                created_tag = store.find_tag(conn, name) is None
                tag_id = store.create_tag(conn, name)
                if created_tag:
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"created tag {tag_id}",
                        journal.row_delete_descriptor("tags", tag_id),
                    )
                if store.add_binary_tag(conn, binary_id, tag_id):
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"tagged binary {binary_id} with tag {tag_id}",
                        journal.row_delete_descriptor(
                            "binary_tags", {"binary_id": binary_id, "tag_id": tag_id}
                        ),
                    )
            for name in sorted(set(current) - set(names)):
                tag_id = current[name]
                link = journal.snapshot_rows(
                    conn,
                    table="binary_tags",
                    where="binary_id = ? AND tag_id = ?",
                    params=(binary_id, tag_id),
                )
                if store.remove_binary_tag(conn, binary_id, tag_id) and link:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"untagged binary {binary_id} from tag {tag_id}",
                        journal.row_restore_descriptor("binary_tags", link),
                    )
            tags = [tag["name"] for tag in store.get_binary_tags(conn, binary_id)]
    payload = {"analysis_id": analysis_id, "binary_id": binary_id, "tags": tags}
    if json_output:
        typer.echo(json.dumps(log.attach(payload)))
        return
    console.print(f"binary {binary_id} tags: {', '.join(tags) or 'none'}")


@app.command("imported-functions")
def imported_functions(
    analysis_id: int = typer.Argument(..., help="Analysis id whose import stubs to list"),
    limit: int = typer.Option(
        store.DEFAULT_IMPORTED_LIMIT, "--limit", help="How many stubs to list"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List an analysis's import stubs with the functions whose source mentions them.

    The callers come from the stored decompilation text, not from an
    engine-reported call graph, and the payload names that method.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if limit < 1 or limit > store.MAX_IMPORTED_LIMIT:
        _fail(f"limit must be between 1 and {store.MAX_IMPORTED_LIMIT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        payload = store.imported_functions(conn, analysis_id, limit=limit)
    if payload is None:
        _fail(f"no analysis with id {analysis_id}", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="magenta", justify="right")
    table.add_column("Address", style="cyan")
    table.add_column("Import")
    table.add_column("Callers", justify="right")
    for row in payload["functions"]:
        table.add_row(
            str(row["id"]),
            hex(int(row["va"])),
            str(row["name"]),
            str(row["caller_count"]),
        )
    console.print(
        f"\n[bold cyan]{payload['count']} of {payload['total']} imported functions"
        "[/bold cyan] (callers from decompilation text)"
    )
    console.print(table)


@app.command()
def analyses(
    status: str | None = typer.Option(None, "--status", help="Only analyses in this state"),
    search: str | None = typer.Option(
        None, "--search", help="Match the binary name or the engine label"
    ),
    order: str = typer.Option(
        store.DEFAULT_ANALYSIS_ORDER, "--order", help="Newest or oldest first"
    ),
    limit: int = typer.Option(
        store.DEFAULT_ANALYSIS_LIMIT, "--limit", help="How many rows to list"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List analyses with their binary, status, size and tags."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if status is not None and status not in store.ANALYSIS_STATUSES:
        _fail(
            f"unknown analysis status: {status};"
            f" expected one of {', '.join(store.ANALYSIS_STATUSES)}",
            json_output,
        )
    if order not in store.ANALYSIS_ORDERS:
        _fail(
            f"unknown order: {order}; expected one of {', '.join(store.ANALYSIS_ORDERS)}",
            json_output,
        )
    if limit < 1 or limit > store.MAX_ANALYSIS_LIMIT:
        _fail(f"limit must be between 1 and {store.MAX_ANALYSIS_LIMIT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = store.list_analyses(conn, status=status, search=search, order=order, limit=limit)
        total = store.count_analyses(conn)
    if json_output:
        typer.echo(json.dumps({"analyses": rows, "count": len(rows), "total": total}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="magenta", justify="right")
    table.add_column("Binary", style="cyan")
    table.add_column("Engine")
    table.add_column("Status")
    table.add_column("Created", style="dim")
    table.add_column("Tags", style="dim")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["binary_name"]),
            str(row["engine"]),
            str(row["status"]),
            str(row["created_at"]),
            ", ".join(row["tags"]) or "n/a",
        )
    console.print(f"\n[bold cyan]{len(rows)} of {total} analyses[/bold cyan]")
    console.print(table)


@app.command("analysis-logs")
def analysis_logs(
    analysis_id: int = typer.Argument(..., help="Analysis id"),
    limit: int = typer.Option(
        analysis_log.DEFAULT_LOG_LIMIT, "--limit", help="How many log entries to show"
    ),
    offset: int = typer.Option(0, "--offset", help="Skip this many of the newest entries"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show an analysis's log entries, newest first."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if limit < 1 or limit > analysis_log.MAX_LOG_LIMIT:
        _fail(f"limit must be between 1 and {analysis_log.MAX_LOG_LIMIT}", json_output)
    if offset < 0:
        _fail("offset must not be negative", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        entries, total = analysis_log.list_entries(conn, analysis_id, limit=limit, offset=offset)
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "logs": entries,
                    "count": len(entries),
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                }
            )
        )
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("When", style="dim")
    table.add_column("Severity")
    table.add_column("Message")
    for entry in entries:
        severity = str(entry["severity"])
        style = {"error": "red", "warn": "yellow"}.get(severity, "cyan")
        table.add_row(
            str(entry["created_at"]), f"[{style}]{severity}[/{style}]", str(entry["message"])
        )
    console.print(f"\n[bold cyan]{len(entries)} of {total} log entries[/bold cyan]")
    console.print(table)


@app.command("analysis-delete")
def analysis_delete(
    analysis_id: int = typer.Argument(..., help="Analysis id to delete"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete one analysis with its functions, scans and log; journaled."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            _fail(f"no analysis with id {analysis_id}", json_output)
        binary_id = int(analysis["binary_id"])
        if store.is_last_analysis_with_functions(conn, analysis_id):
            _fail(
                f"analysis {analysis_id} is binary {binary_id}'s only analysis and holds"
                f" functions; delete binary {binary_id} instead",
                json_output,
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_analysis_delete(conn, log, analysis_id)
    if json_output:
        typer.echo(json.dumps(log.attach({"analysis_id": analysis_id, "binary_id": binary_id})))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Deleted[/green] analysis {analysis_id} of binary {binary_id}")


# ── journal ────────────────────────────────────────────────────────


def _journal_error_text(exc: Exception) -> str:
    """Return a journal failure's message without the KeyError quoting."""
    return str(exc.args[0]) if exc.args else str(exc)


@app.command("jobs")
def jobs_command(
    status: str | None = typer.Option(None, "--status", help="Only jobs in this status"),
    kind: str | None = typer.Option(None, "--kind", help="Only jobs of this kind"),
    limit: int = typer.Option(jobs.DEFAULT_JOB_LIMIT, "--limit", help="How many jobs to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List queued and finished jobs, newest first."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            rows, total = jobs.list_jobs(conn, status=status, kind=kind, limit=limit)
        except ValueError as exc:
            _fail(str(exc), json_output)
        queued = jobs.count_jobs(conn, status=jobs.STATUS_QUEUED)
    if json_output:
        typer.echo(json.dumps({"jobs": rows, "count": len(rows), "total": total, "queued": queued}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Id", justify="right")
    table.add_column("Kind", style="cyan")
    table.add_column("Binary", justify="right")
    table.add_column("Status")
    table.add_column("Created")
    table.add_column("Message")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["kind"]),
            str(row["binary_id"]),
            str(row["status"]),
            str(row["created_at"]),
            str(row["error"] or row["message"]),
        )
    console.print(table)
    console.print(f"\n[bold cyan]{queued}[/bold cyan] waiting, {total} matching")


@app.command("job")
def job_command(
    job_id: int = typer.Argument(..., help="Job id to read"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show one job with its status, progress and result or error."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        job = jobs.get_job(conn, job_id)
    if job is None:
        _fail(f"no job with id {job_id}", json_output)
    if json_output:
        typer.echo(json.dumps(job))
        return
    console.print(f"job {job['id']}: {job['kind']} on binary {job['binary_id']}")
    console.print(f"  status:   {job['status']} ({job['progress']}/{job['steps_total']})")
    console.print(f"  message:  {job['message'] or '-'}")
    if job["error"]:
        console.print(f"  error:    {job['error']}")
    if job["result"] is not None:
        typer.echo(json.dumps(job["result"], indent=2))


@app.command("job-submit")
def job_submit_command(
    kind: str = typer.Argument(..., help=f"One of: {', '.join(jobs.JOB_KINDS)}"),
    binary_id: int = typer.Argument(..., help="Binary to run it on"),
    domain: str | None = typer.Option(
        None, "--domain", help="Domain a behavior or hardening job scans"
    ),
    run: bool = typer.Option(False, "--run", help="Run it now instead of leaving it queued"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Queue one operation; the server's pool picks it up, or --run does it now."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    params = {"domain": domain} if domain else {}
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                job = jobs.submit(conn, kind=kind, binary_id=binary_id, params=params)
            except KeyError as exc:
                _fail(_journal_error_text(exc), json_output)
            except ValueError as exc:
                _fail(str(exc), json_output)
            journal.journaled_create(
                log,
                table=jobs.TABLE,
                key=int(job["id"]),
                description=f"queued {kind} job {job['id']} for binary {binary_id}",
            )
        if run:
            job = jobs.run_pending(conn, limit=1)[0]
    if json_output:
        typer.echo(json.dumps(job))
        return
    console.print(f"job {job['id']}: {job['status']}")


@app.command("job-run")
def job_run_command(
    limit: int = typer.Option(1, "--limit", help="How many waiting jobs to run"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Run the oldest waiting jobs inline, in this process."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if limit < 1:
        _fail("limit must be positive", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        finished = jobs.run_pending(conn, limit=limit)
    if json_output:
        typer.echo(json.dumps({"jobs": finished, "count": len(finished)}))
        return
    if not finished:
        console.print("no job was waiting")
        return
    for job in finished:
        console.print(f"job {job['id']}: {job['status']} {job['error']}".rstrip())


@app.command("job-cancel")
def job_cancel_command(
    job_id: int = typer.Argument(..., help="Job id to cancel"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Cancel a job that has not started; a running one cannot be stopped."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if jobs.get_job(conn, job_id) is None:
            _fail(f"no job with id {job_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=jobs.TABLE,
                where="id = ?",
                params=(job_id,),
                description=f"cancelled job {job_id}",
            )
            try:
                job = jobs.cancel(conn, job_id)
            except ValueError as exc:
                _fail(str(exc), json_output)
        job = log.attach(job or {})
    if json_output:
        typer.echo(json.dumps(job))
        return
    console.print(f"job {job['id']}: {job['status']}")


@app.command("notifications")
def notifications_command(
    since: str | None = typer.Option(
        None, "--since", help="Only items newer than this ISO timestamp"
    ),
    limit: int = typer.Option(
        notifications.DEFAULT_FEED_LIMIT, "--limit", help="How many items to list"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show the notification feed derived from the journal and the analysis log."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = notifications.feed(
                conn,
                since=notifications.parse_since(since) if since else None,
                limit=limit,
            )
        except ValueError as exc:
            _fail(str(exc), json_output)
        payload["latest"] = notifications.latest(conn)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("When", style="cyan")
    table.add_column("Source")
    table.add_column("Severity")
    table.add_column("Item")
    for item in payload["notifications"]:
        table.add_row(
            str(item["at"]),
            str(item["kind"]),
            str(item["severity"]),
            str(item["message"]),
        )
    console.print(table)
    if payload["latest"]:
        console.print(f"\n[bold cyan]latest[/bold cyan] {payload['latest']}")


@app.command("journal")
def journal_command(
    action: str | None = typer.Option(None, "--action", help="Only the entries of one action id"),
    limit: int = typer.Option(
        journal.DEFAULT_LIST_LIMIT, "--limit", help="How many entries to list"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List recorded action-journal entries, newest first."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if limit < 1:
        _fail("limit must be positive", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        entries = journal.list_entries(conn, action=action, limit=limit)
    if json_output:
        typer.echo(json.dumps({"entries": entries, "count": len(entries)}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Action", style="cyan")
    table.add_column("Kind")
    table.add_column("Status")
    table.add_column("Created")
    table.add_column("Description")
    for entry in entries:
        table.add_row(
            str(entry["action"]),
            str(entry["kind"]),
            str(entry["status"]),
            str(entry["created_at"]),
            str(entry["description"]),
        )
    console.print(f"\n[bold cyan]{portal_db}[/bold cyan]")
    console.print(table)


@app.command("journal-revert")
def journal_revert_command(
    action: str | None = typer.Option(None, "--action", help="Action id to revert"),
    entry: int | None = typer.Option(None, "--entry", help="One journal entry id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Revert one recorded action or one journal entry."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if (action is None) == (entry is None):
        _fail("provide exactly one of --action or --entry", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            if entry is not None:
                payload = journal.revert_entry(conn, entry)
            else:
                payload = journal.revert_action(conn, str(action))
        except (journal.UnknownActionError, journal.UnknownEntryError) as exc:
            _fail(_journal_error_text(exc), json_output)
        except journal.EntryNotActiveError as exc:
            _fail(str(exc), json_output)
        except journal.JournalError:
            _fail("the stored journal entry is unreadable", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if entry is not None:
        console.print(f"[green]{payload['status']}[/green] journal entry {entry}")
        return
    console.print(
        f"[green]Reverted[/green] {payload['reverted']} of"
        f" {payload['reverted'] + payload['failed']} entries of action {payload['action']}"
    )
    for reported in payload["entries"]:
        if reported["status"] in {"reverted", "partial"}:
            continue
        console.print(f"  [yellow]{reported['status']}[/yellow] {reported['description']}")


# ── revert ─────────────────────────────────────────────────────────


@app.command()
def revert(
    function_id: int = typer.Argument(..., help="Function id whose name to restore"),
    history_id: int = typer.Argument(..., help="Rename-history id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Restore a function name recorded in its rename history."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        entry = store.get_name_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            _fail(f"no history {history_id} for function {function_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                journal.journaled_revert_name(conn, log, function_id, history_id)
            except ValueError as exc:
                _fail(str(exc), json_output)
        name = str(entry["old_name"])
    payload = log.attach({"function_id": function_id, "history_id": history_id, "name": name})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Reverted[/green] function {function_id} to {name!r}")
    _print_journal_action(log, json_output)


# ── tags ───────────────────────────────────────────────────────────


@app.command()
def tags(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List tags and how many binaries carry each."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = store.list_tags(conn)
    if json_output:
        typer.echo(json.dumps({"tags": rows}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tag", style="cyan")
    table.add_column("Binaries", justify="right")
    for row in rows:
        table.add_row(str(row["name"]), str(row["binary_count"]))
    console.print(table)


@app.command()
def tag(
    binary_id: int = typer.Argument(..., help="Binary id to tag"),
    name: str = typer.Argument(..., help="Tag name"),
    remove: bool = typer.Option(False, "--remove", help="Remove the tag instead of adding it"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add or remove one tag on a binary, addressed by name."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if remove:
                known = store.find_tag(conn, name)
                if known is None:
                    _fail(f"no tag named {name!r}", json_output)
                tag_id = int(known["id"])
                link = journal.snapshot_rows(
                    conn,
                    table="binary_tags",
                    where="binary_id = ? AND tag_id = ?",
                    params=(binary_id, tag_id),
                )
                if not store.remove_binary_tag(conn, binary_id, tag_id):
                    _fail(f"binary {binary_id} does not have tag {name!r}", json_output)
                if link:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"untagged binary {binary_id} from tag {tag_id}",
                        journal.row_restore_descriptor("binary_tags", link),
                    )
                payload: dict[str, Any] = {
                    "binary_id": binary_id,
                    "tag_id": tag_id,
                    "name": name,
                    "removed": True,
                }
            else:
                created = store.find_tag(conn, name) is None
                tag_id = store.create_tag(conn, name)
                added = store.add_binary_tag(conn, binary_id, tag_id)
                if created:
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"created tag {tag_id}",
                        journal.row_delete_descriptor("tags", tag_id),
                    )
                if added:
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"tagged binary {binary_id} with tag {tag_id}",
                        journal.row_delete_descriptor(
                            "binary_tags", {"binary_id": binary_id, "tag_id": tag_id}
                        ),
                    )
                payload = {
                    "binary_id": binary_id,
                    "tag_id": tag_id,
                    "name": name,
                    "added": added,
                }
        payload = log.attach(payload)
    if json_output:
        typer.echo(json.dumps(payload))
    elif remove:
        console.print(f"[green]Removed[/green] tag {name!r} from binary {binary_id}")
    else:
        verb = "Tagged" if payload["added"] else "Already tagged"
        console.print(f"[green]{verb}[/green] binary {binary_id} with {name!r}")
    _print_journal_action(log, json_output)


@app.command()
def config(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Report what this instance can do: versions, features, limits and counts."""
    payload = instance.describe()
    if json_output:
        typer.echo(json.dumps(payload))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("reportal", str(payload["version"]))
    table.add_row("engine", "available" if payload["engine"]["available"] else "unavailable")
    table.add_row("database", f"{payload['database']['tables']} tables")
    table.add_row("MCP tools", str(payload["mcp"]["total"]))
    for name, value in sorted(payload["features"].items()):
        table.add_row(
            f"feature: {name}", ", ".join(value) if isinstance(value, list) else str(value)
        )
    for name, value in sorted(payload["limits"].items()):
        table.add_row(f"limit: {name}", str(value))
    console.print(table)


# ── collections ────────────────────────────────────────────────────


def _require_collection(
    conn: sqlite3.Connection, collection_id: int, json_output: bool
) -> dict[str, Any]:
    """Return one collection row or fail the command with its id named."""
    collection = store.get_collection(conn, collection_id)
    if collection is None:
        _fail(f"no collection with id {collection_id}", json_output)
    return collection


@app.command()
def collections(
    order: str = typer.Option(
        store.DEFAULT_COLLECTION_ORDER,
        "--order",
        help=f"Sort by one of: {', '.join(store.COLLECTION_ORDERS)}",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List collections with their member and tag counts."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            rows = store.list_collections(conn, order=order)
        except ValueError as exc:
            _fail(str(exc), json_output)
        for row in rows:
            row["tags"] = [tag["name"] for tag in store.collection_tags(conn, int(row["id"]))]
    if json_output:
        typer.echo(json.dumps({"collections": rows, "order": order}))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Id", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("Binaries", justify="right")
    table.add_column("Tags")
    table.add_column("Description")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["name"]),
            str(row["binary_count"]),
            ", ".join(row["tags"]),
            str(row["description"]),
        )
    console.print(table)


@app.command()
def collection_show(
    collection_id: int = typer.Argument(..., help="Collection id"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show one collection with its members and tags."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        collection = _require_collection(conn, collection_id, json_output)
    if json_output:
        typer.echo(json.dumps(collection))
        return
    console.print(f"[bold]{collection['name']}[/bold] (id {collection['id']})")
    if collection["description"]:
        console.print(collection["description"])
    table = Table(show_header=True, header_style="bold")
    table.add_column("Binary", justify="right")
    table.add_column("Name", style="cyan")
    for row in collection["binaries"]:
        table.add_row(str(row["id"]), str(row["name"]))
    console.print(table)
    if collection["tags"]:
        console.print("Tags: " + ", ".join(str(tag["name"]) for tag in collection["tags"]))


@app.command()
def collection_new(
    name: str = typer.Argument(..., help="Collection name"),
    description: str = typer.Option("", "--description", help="Free-text description"),
    scope: str = typer.Option("", "--scope", help="Scope label"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Create a collection."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                collection_id = store.create_collection(
                    conn, name=name, description=description, scope=scope
                )
            except ValueError as exc:
                _fail(str(exc), json_output)
            journal.journaled_create(
                log,
                table="collections",
                key=collection_id,
                description=f"created collection {collection_id}",
            )
            payload = log.attach({"collection_id": collection_id, "name": name})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Created[/green] collection {collection_id} ({name})")
    _print_journal_action(log, json_output)


@app.command()
def collection_edit(
    collection_id: int = typer.Argument(..., help="Collection id"),
    name: str = typer.Option(None, "--name", help="New name"),
    description: str = typer.Option(None, "--description", help="New description"),
    scope: str = typer.Option(None, "--scope", help="New scope label"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rename a collection or set its description and scope; omitted fields stay."""
    if name is None and description is None and scope is None:
        _fail("nothing to change: pass --name, --description or --scope", json_output)
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        _require_collection(conn, collection_id, json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="collections",
                where="id = ?",
                params=(collection_id,),
                description=f"updated collection {collection_id}",
            )
            try:
                collection = store.update_collection(
                    conn, collection_id, name=name, description=description, scope=scope
                )
            except ValueError as exc:
                _fail(str(exc), json_output)
            payload = log.attach(collection or {})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Updated[/green] collection {collection_id}")
    _print_journal_action(log, json_output)


@app.command()
def collection_rm(
    collection_id: int = typer.Argument(..., help="Collection id"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete a collection with its membership and tag links."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        _require_collection(conn, collection_id, json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # Links before the parent row: a revert replays newest-first and a
            # link restored before its parent exists trips the foreign key.
            for table in ("collection_binaries", "collection_tags"):
                links = journal.snapshot_rows(
                    conn, table=table, where="collection_id = ?", params=(collection_id,)
                )
                if links:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"links of collection {collection_id} in {table}",
                        journal.row_restore_descriptor(table, links),
                    )
            journal.journaled_rows(
                conn,
                log,
                table="collections",
                where="id = ?",
                params=(collection_id,),
                description=f"deleted collection {collection_id}",
            )
            store.delete_collection(conn, collection_id)
            payload = log.attach({"collection_id": collection_id, "deleted": True})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Deleted[/green] collection {collection_id}")
    _print_journal_action(log, json_output)


@app.command()
def collection_add(
    collection_id: int = typer.Argument(..., help="Collection id"),
    binary_id: list[int] = typer.Argument(..., help="Binary ids to add"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add binaries to a collection, keeping the ones already in it."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        collection = _require_collection(conn, collection_id, json_output)
        current = [int(row["id"]) for row in collection["binaries"]]
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="collection_binaries",
                where="collection_id = ?",
                params=(collection_id,),
            )
            try:
                change = store.replace_collection_binaries(
                    conn, collection_id, [*current, *binary_id]
                )
            except ValueError as exc:
                _fail(str(exc), json_output)
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"members of collection {collection_id}",
                journal.row_restore_descriptor("collection_binaries", before),
            )
            payload = log.attach({"collection_id": collection_id, **change})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        added = len(payload["added"])
        console.print(f"[green]Added[/green] {added} binary(ies) to collection {collection_id}")
    _print_journal_action(log, json_output)


@app.command()
def collection_remove(
    collection_id: int = typer.Argument(..., help="Collection id"),
    binary_id: list[int] = typer.Argument(..., help="Binary ids to remove"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove binaries from a collection, keeping the other members."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    drop = set(binary_id)
    with contextlib.closing(store.connect(portal_db)) as conn:
        collection = _require_collection(conn, collection_id, json_output)
        kept = [int(row["id"]) for row in collection["binaries"] if int(row["id"]) not in drop]
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="collection_binaries",
                where="collection_id = ?",
                params=(collection_id,),
            )
            change = store.replace_collection_binaries(conn, collection_id, kept)
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"members of collection {collection_id}",
                journal.row_restore_descriptor("collection_binaries", before),
            )
            payload = log.attach({"collection_id": collection_id, **change})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(
            f"[green]Removed[/green] {len(payload['removed'])} binary(ies)"
            f" from collection {collection_id}"
        )
    _print_journal_action(log, json_output)


@app.command()
def collection_tags(
    collection_id: int = typer.Argument(..., help="Collection id"),
    tag: list[str] = typer.Argument(None, help="The tag names the collection should carry"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Replace a collection's tags with the names given (none clears them)."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        _require_collection(conn, collection_id, json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn, table="collection_tags", where="collection_id = ?", params=(collection_id,)
            )
            change = store.set_collection_tags(conn, collection_id, list(tag or []))
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"tags of collection {collection_id}",
                journal.row_restore_descriptor("collection_tags", before),
            )
            payload = log.attach({"collection_id": collection_id, **change})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(
            f"[green]Tagged[/green] collection {collection_id}:"
            f" +{len(payload['added'])} -{len(payload['removed'])}"
        )
    _print_journal_action(log, json_output)


# ── Comments ───────────────────────────────────────────────────────


def _comment_error_text(exc: comments.CommentError) -> str:
    """Return a comment failure's message without the KeyError quoting."""
    return str(exc.args[0]) if exc.args else str(exc)


def _comment_scope(
    binary_id: int | None, function_id: int | None, json_output: bool
) -> tuple[str, int]:
    """Resolve the ``--binary``/``--function`` pair to one existing scope."""
    if (binary_id is None) == (function_id is None):
        _fail("provide exactly one of --binary or --function", json_output)
    if binary_id is not None:
        return comments.SCOPE_BINARY, binary_id
    return comments.SCOPE_FUNCTION, cast(int, function_id)


def _print_comments(rows: list[dict[str, Any]]) -> None:
    if not rows:
        console.print("[yellow]No comments.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", justify="right", style="magenta")
    table.add_column("Author", style="cyan")
    table.add_column("Created")
    table.add_column("Updated")
    table.add_column("Body")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["author"]),
            str(row["created_at"]),
            str(row["updated_at"]),
            escape(str(row["body"])),
        )
    console.print(table)


@app.command("comments")
def comments_list(
    binary: int | None = typer.Option(None, "--binary", help="Binary id whose comments to list"),
    function_id: int | None = typer.Option(
        None, "--function", help="Function id whose comments to list"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the analyst comments stored on one binary or function."""
    scope_kind, scope_id = _comment_scope(binary, function_id, json_output)
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            rows = comments.list_comments(conn, scope_kind=scope_kind, scope_id=scope_id)
        except comments.CommentError as exc:
            _fail(_comment_error_text(exc), json_output)
    if json_output:
        typer.echo(json.dumps({"comments": rows}))
        return
    _print_comments(rows)


@app.command("comment-add")
def comment_add(
    text: str = typer.Argument(..., help="Comment body"),
    binary: int | None = typer.Option(None, "--binary", help="Binary id to comment on"),
    function_id: int | None = typer.Option(None, "--function", help="Function id to comment on"),
    author: str = typer.Option("", "--author", help="Author name"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Store one analyst comment on a binary or function."""
    scope_kind, scope_id = _comment_scope(binary, function_id, json_output)
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                created = comments.add_comment(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    body=text,
                    author=author or None,
                )
            except comments.CommentError as exc:
                _fail(_comment_error_text(exc), json_output)
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"stored comment {created['id']}",
                journal.row_delete_descriptor("comments", int(created["id"])),
            )
        payload = log.attach(created)
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(
            f"[green]Stored[/green] comment {created['id']}"
            f" on {scope_kind} {scope_id} by {created['author']}"
        )
    _print_journal_action(log, json_output)


@app.command("comment-rm")
def comment_rm(
    comment_id: int = typer.Argument(..., help="Comment id to delete"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete one analyst comment by id."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn, table="comments", where="id = ?", params=(comment_id,)
            )
            try:
                deleted = comments.delete_comment(conn, comment_id)
            except comments.CommentError as exc:
                _fail(_comment_error_text(exc), json_output)
            if before:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"deleted comment {comment_id}",
                    journal.row_restore_descriptor("comments", before),
                )
        payload = log.attach({"comment": deleted, "comment_id": comment_id, "deleted": True})
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Deleted[/green] comment {comment_id}")
    _print_journal_action(log, json_output)


# ── Bulk actions ───────────────────────────────────────────────────


def _print_bulk_result(result: dict[str, Any]) -> None:
    console.print(
        f"[green]{result['applied']}[/green] of {result['requested']} applied"
        f" for action {result['action']}"
    )
    for entry in result["skipped"]:
        console.print(f"  [yellow]skipped[/yellow] {entry['id']}: {entry['reason']}")


def _run_bulk(portal_db: Path, apply: Any, json_output: bool) -> dict[str, Any]:
    """Open *portal_db*, run one journaled bulk apply, and report its action id."""
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = apply(conn, log)
            except bulk_actions.BulkError as exc:
                _fail(f"invalid bulk request: {exc}", json_output)
        result = log.attach(result)
    _print_journal_action(log, json_output)
    return result


@app.command("bulk-tag")
def bulk_tag(
    tag: str = typer.Argument(..., help="Tag name"),
    binary_ids: list[int] = typer.Argument(..., help="Binary ids to tag"),
    remove: bool = typer.Option(False, "--remove", help="Remove the tag instead of adding it"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add or remove one tag across many binaries."""
    action = "remove_tag" if remove else "add_tag"
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    result = _run_bulk(
        portal_db,
        lambda conn, log: bulk_actions.apply_binary_action(
            conn, action=action, ids=binary_ids, tag=tag, log=log
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(result))
        return
    _print_bulk_result(result)


@app.command("bulk-delete")
def bulk_delete(
    binary_ids: list[int] = typer.Argument(..., help="Binary ids to delete"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete many binaries and everything scoped to them."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not yes:
        listed = ", ".join(str(binary_id) for binary_id in binary_ids)
        if not typer.confirm(f"Delete binaries {listed} and everything scoped to them?"):
            _fail("aborted", json_output)
    result = _run_bulk(
        portal_db,
        lambda conn, log: bulk_actions.apply_binary_action(
            conn, action="delete", ids=binary_ids, log=log
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(result))
        return
    _print_bulk_result(result)


@app.command("analysis-bulk-tag")
def analysis_bulk_tag(
    tag: str = typer.Argument(..., help="Tag name"),
    analysis_ids: list[int] = typer.Argument(..., help="Analysis ids whose binaries to tag"),
    remove: bool = typer.Option(False, "--remove", help="Remove the tag instead of adding it"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add or remove one tag across the binaries many analyses belong to."""
    action = "remove_tag" if remove else "add_tag"
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    result = _run_bulk(
        portal_db,
        lambda conn, log: bulk_actions.apply_analysis_action(
            conn, action=action, ids=analysis_ids, tag=tag, log=log
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(result))
        return
    _print_bulk_result(result)


@app.command("analysis-bulk-delete")
def analysis_bulk_delete(
    analysis_ids: list[int] = typer.Argument(..., help="Analysis ids to delete"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete many analyses with the rows scoped to them.

    A binary's only analysis while it holds functions is skipped with a reason
    rather than taken with them, exactly as the single-analysis delete refuses
    it: delete the binary instead.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not yes:
        listed = ", ".join(str(analysis_id) for analysis_id in analysis_ids)
        if not typer.confirm(f"Delete analyses {listed} and the rows scoped to them?"):
            _fail("aborted", json_output)
    result = _run_bulk(
        portal_db,
        lambda conn, log: bulk_actions.apply_analysis_action(
            conn, action="delete", ids=analysis_ids, log=log
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(result))
        return
    _print_bulk_result(result)


@app.command("bulk-prefix")
def bulk_prefix(
    prefix: str = typer.Argument(..., help="Prefix to apply to each function name"),
    function_ids: list[int] = typer.Argument(..., help="Function ids to rename"),
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Drop the name's leading segment up to the first underscore before adding the prefix",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Apply a prefix to many function names, recording each rename in history."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    result = _run_bulk(
        portal_db,
        lambda conn, log: bulk_actions.apply_function_action(
            conn, action="rename", ids=function_ids, prefix=prefix, replace=replace, log=log
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(result))
        return
    _print_bulk_result(result)


# ── apply-match ────────────────────────────────────────────────────


@app.command("apply-match")
def apply_match(
    function_id: int = typer.Argument(..., help="Function id that receives the symbol"),
    candidate_function_id: int = typer.Argument(..., help="Recorded match candidate id"),
    mode: str = typer.Option(
        matching.DEFAULT_TRANSFER_MODE,
        "--mode",
        help="What to copy: name, signature or both",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Copy a recorded match candidate's name, signature, or both onto a function.

    A signature transfer replaces the target's return type, calling convention
    and parameters, and is refused when the target already carries a different
    non-empty calling convention.  A referenced local type the target's binary
    has no row for is reported, not dropped.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            plan = matching.plan_transfer(
                conn,
                function_id=function_id,
                candidate_function_id=candidate_function_id,
                mode=mode,
            )
        except matching.InvalidSettingsError as exc:
            _fail(exc.detail, json_output)
        if plan.status == matching.TRANSFER_STATUS_FAILED:
            _fail(plan.detail, json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if plan.status == matching.TRANSFER_STATUS_APPLIED:
                matching.apply_transfer(conn, log, plan, actor="cli")
        payload = log.attach(matching.plan_payload(plan))
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if plan.status == matching.TRANSFER_STATUS_SKIPPED:
        console.print(f"[yellow]Function {function_id} already matches; nothing changed.[/yellow]")
    else:
        if plan.renames:
            console.print(
                f"[green]Renamed[/green] function {function_id}:"
                f" {plan.old_name!r} -> {plan.new_name!r}"
            )
        if plan.writes_signature:
            console.print(
                f"[green]Copied the signature[/green] of candidate {candidate_function_id}"
                f" onto function {function_id}"
            )
        if plan.missing_types:
            console.print(
                "[yellow]Referenced types with no local definition:[/yellow]"
                f" {', '.join(plan.missing_types)}"
            )
    _print_journal_action(log, json_output)


# ── diff ───────────────────────────────────────────────────────────

# Width of the line-number gutter `reportal diff` prints; the numbers come
# from the two listings' own 1-based numbering.
_DIFF_LINE_NUMBER_WIDTH = 5


def _function_label(side: dict[str, Any]) -> str:
    """Name one side of a diff as ``#id name @ 0xva``."""
    name = str(side["name"]).strip() or f"#{side['function_id']}"
    return f"#{side['function_id']} {name} @ 0x{int(side['va']):x}"


def _print_diff(payload: dict[str, Any]) -> None:
    """Print one diff as a unified-style listing plus its summary counts."""
    score = payload["similarity"]
    rendered_score = "n/a" if score is None else f"{float(score):.1f}"
    console.print(
        f"[bold cyan]diff[/bold cyan] {payload['kind']}"
        f" · {escape(_function_label(payload['left']))}"
        f" -> {escape(_function_label(payload['right']))}"
    )
    console.print(f"similarity {rendered_score} · normalized {payload['normalized']}")
    for entry in payload["entries"]:
        line_number = entry["left_line"] or entry["right_line"]
        op = str(entry["op"])
        text = entry["left"] if entry["left"] is not None else entry["right"]
        gutter = f"{line_number:>{_DIFF_LINE_NUMBER_WIDTH}}"
        body = escape(str(text or ""))
        if op == "delete":
            console.print(f"{gutter} [red]- {body}[/red]")
        elif op in {"insert", "replace"}:
            console.print(f"{gutter} [green]+ {body}[/green]")
        else:
            console.print(f"{gutter}   {body}")
    summary = payload["summary"]
    console.print(
        f"equal {summary['equal']} · insert {summary['insert']}"
        f" · delete {summary['delete']} · changed {summary['changed']}"
    )


@app.command()
def diff(
    function_id: int = typer.Argument(..., help="Function id (left side)"),
    candidate_function_id: int = typer.Argument(..., help="Candidate function id (right side)"),
    kind: str = typer.Option(
        diffview.DEFAULT_KIND, "--kind", help="Listing kind: disasm or decomp"
    ),
    normalize: bool = typer.Option(
        True,
        "--normalize/--no-normalize",
        help="Strip addresses, encoded bytes and comments before comparing",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Align a function against a match candidate and print the differences."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if kind not in diffview.DIFF_KINDS:
        _fail(f"unsupported diff kind: {kind}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = diffview.function_diff(
                conn,
                engines.get_engine(),
                function_id=function_id,
                candidate_id=candidate_function_id,
                kind=kind,
                normalize=normalize,
            )
        except diffview.DiffError as exc:
            _fail(exc.detail, json_output)

    if json_output:
        typer.echo(json.dumps(payload))
        return
    _print_diff(payload)


# ── lineage ────────────────────────────────────────────────────────

# Changed, removed and added rows the human table renders before it stops; the
# JSON payload always carries every row the comparison returned.
_LINEAGE_ROWS_SHOWN = 50


def _lineage_label(name: Any, va: Any) -> str:
    """Render one side of a lineage row as ``name @ 0xva``, or ``n/a``."""
    if name is None and va is None:
        return "n/a"
    rendered = str(name).strip() if name else "?"
    return f"{rendered} @ 0x{int(va):x}" if va is not None else rendered


def _print_lineage(payload: dict[str, Any]) -> None:
    """Print a comparison's counts plus its changed, removed and added rows."""
    summary = payload["summary"]
    console.print(
        f"[bold cyan]lineage[/bold cyan] {escape(str(payload['left_name']))}"
        f" -> {escape(str(payload['right_name']))}"
    )
    console.print(
        f"unchanged {summary['unchanged']} · changed {summary['changed']}"
        f" · removed {summary['removed']} · added {summary['added']}"
        f" · matched {summary['matched_percent']}%"
    )
    console.print(f"refined: {'yes' if payload['refined'] else 'no'}")
    rows = [row for row in payload["rows"] if row["status"] != lineage.STATUS_UNCHANGED]
    if not rows:
        console.print("[green]No changed, removed or added functions.[/green]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Status", style="cyan")
    table.add_column("Left")
    table.add_column("Right")
    table.add_column("Similarity")
    for row in rows[:_LINEAGE_ROWS_SHOWN]:
        similarity = row["similarity"]
        table.add_row(
            str(row["status"]),
            _lineage_label(row["left_name"], row["left_va"]),
            _lineage_label(row["right_name"], row["right_va"]),
            "n/a" if similarity is None else f"{float(similarity):.1f}",
        )
    console.print(table)
    if len(rows) > _LINEAGE_ROWS_SHOWN:
        console.print(f"[yellow]Showing {_LINEAGE_ROWS_SHOWN} of {len(rows)} rows.[/yellow]")


@app.command("lineage")
def lineage_command(
    left_binary_id: int = typer.Argument(..., help="Left binary id"),
    right_binary_id: int = typer.Argument(..., help="Right binary id"),
    refine: bool = typer.Option(
        True,
        "--refine/--no-refine",
        help="Refine placeholder pairings with structural similarity",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compare two binaries' functions and report what differs between them."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if left_binary_id == right_binary_id:
        _fail(f"binary {left_binary_id} cannot be compared with itself", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = lineage.compare_binaries(
                conn,
                left_binary_id=left_binary_id,
                right_binary_id=right_binary_id,
                engine=engines.get_engine(),
                refine=refine,
            )
        except KeyError as exc:
            _fail(str(exc.args[0]), json_output)
        except lineage.SameBinaryError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(payload))
        return
    _print_lineage(payload)


# ── families and detect ────────────────────────────────────────────


def _print_families(rows: list[dict[str, Any]]) -> None:
    """Print the registered families as an id/name/aliases/reference table."""
    if not rows:
        console.print("[yellow]No families registered.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Aliases")
    table.add_column("Reference", justify="right")
    for row in rows:
        aliases = ", ".join(str(alias) for alias in row["aliases"])
        table.add_row(
            str(row["family_id"]),
            escape(str(row["name"])),
            aliases or "n/a",
            str(row["reference_binary_id"]),
        )
    console.print(table)


def _print_detection(result: dict[str, Any]) -> None:
    """Print a detection's match count and each match's signals."""
    console.print(
        f"[bold cyan]binary {result['binary_id']}[/bold cyan]"
        f" {result['count']} matches of {result['families_checked']} families"
    )
    if not result["matches"]:
        console.print("[yellow]No family matched.[/yellow]")
    for match in result["matches"]:
        console.print(f"[bold]{escape(str(match['name']))}[/bold] ({match['confidence']})")
        for signal in match["signals"]:
            console.print(f"  {signal['kind']}: {escape(str(signal['detail']))}")
    for note in result.get("notes", []):
        console.print(f"[dim]{escape(str(note))}[/dim]")


@app.command("families")
def families_command(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the locally registered malware families."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = families.list_families(conn)
    if json_output:
        typer.echo(json.dumps({"families": rows}))
        return
    _print_families(rows)


@app.command("family-add")
def family_add(
    reference_binary_id: int = typer.Argument(..., help="Reference binary id"),
    name: str = typer.Argument(..., help="Family name"),
    alias: list[str] | None = typer.Option(None, "--alias", help="Alias (repeatable)"),
    notes: str = typer.Option("", "--notes", help="Free-form notes"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Register a family from a reference binary and store its signatures."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                family = families.register_family(
                    conn,
                    name=name,
                    reference_binary_id=reference_binary_id,
                    aliases=[value for value in (alias or []) if value.strip()],
                    notes=notes,
                    engine=engines.get_engine(),
                )
            except families.FamilyError as exc:
                _fail(str(exc), json_output)
            except engines.EngineUnavailable as exc:
                _fail(str(exc), json_output)
            except KeyError as exc:
                _fail(str(exc.args[0]), json_output)
            except FileNotFoundError as exc:
                _fail(str(exc), json_output)
            except engines.EngineError as exc:
                _fail(str(exc), json_output)
            journal.journaled_create(
                log,
                table="families",
                key=int(family["family_id"]),
                description=f"registered family {family['family_id']}",
            )

    if json_output:
        typer.echo(json.dumps(log.attach(family)))
        return
    _print_journal_action(log, json_output)
    signatures = family["signatures"]
    console.print(
        f"[green]Registered[/green] family {family['family_id']}: {escape(str(family['name']))}"
    )
    console.print(f"reference binary {family['reference_binary_id']}")
    console.print(
        f"sha256 {signatures.get('sha256') or 'n/a'}"
        f" · import hash {signatures.get('import_hash', '')}"
        f" · {len(signatures.get('import_names', []))} imports"
        f" · {len(signatures.get('capabilities', []))} capabilities"
    )


@app.command("family-rm")
def family_rm(
    family_id: int = typer.Argument(..., help="Family id to delete"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Delete a locally registered malware family."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="families",
                where="id = ?",
                params=(family_id,),
                description=f"deleted family {family_id}",
            )
            removed = families.delete_family(conn, family_id)
            if not removed:
                _fail(f"no family with id {family_id}", json_output)
    if json_output:
        typer.echo(json.dumps(log.attach({"family_id": family_id, "deleted": True})))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Deleted[/green] family {family_id}")


@app.command("detect")
def detect_command(
    binary_id: int = typer.Argument(..., help="Binary id to match"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Match a binary against the locally registered malware families."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_DETECT,
                lambda: families.detect_binary(
                    conn, binary_id=binary_id, engine=engines.get_engine()
                ),
            )
        except engines.EngineUnavailable as exc:
            _fail(str(exc), json_output)
        except KeyError as exc:
            _fail(str(exc.args[0]), json_output)
        except FileNotFoundError as exc:
            _fail(str(exc), json_output)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _print_detection(result)


# ── related ────────────────────────────────────────────────────────

# Candidate rows the human table renders before it stops; the JSON payload
# always carries every row the scan returned.
_RELATED_ROWS_SHOWN = 50


def _print_related(payload: dict[str, Any]) -> None:
    """Print a relationship scan's candidate count and its ranked rows."""
    console.print(
        f"[bold cyan]binary {payload['binary_id']}[/bold cyan]"
        f" {payload['count']} related of {payload['candidates_considered']} candidates"
    )
    rows = payload["related"]
    if not rows:
        console.print("[yellow]No related binary found.[/yellow]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Classification", style="cyan")
        table.add_column("Confidence")
        table.add_column("Name")
        table.add_column("Similarity", justify="right")
        table.add_column("Signals")
        for row in rows[:_RELATED_ROWS_SHOWN]:
            table.add_row(
                str(row["classification"]),
                str(row["confidence"]),
                escape(str(row["name"])),
                f"{float(row['similarity']):.3f}",
                ", ".join(str(signal["kind"]) for signal in row["signals"]) or "n/a",
            )
        console.print(table)
        if len(rows) > _RELATED_ROWS_SHOWN:
            console.print(f"[yellow]Showing {_RELATED_ROWS_SHOWN} of {len(rows)} rows.[/yellow]")
    for note in payload.get("notes", []):
        console.print(f"[dim]{escape(str(note))}[/dim]")


@app.command("related")
def related_command(
    binary_id: int = typer.Argument(..., help="Binary id to rank the others against"),
    limit: int = typer.Option(
        related.DEFAULT_LIMIT, "--limit", help="Maximum related binaries to list"
    ),
    include_unrelated: bool = typer.Option(
        False, "--all", help="Include binaries with no relationship"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rank the other stored binaries by their relationship to this one."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            log, payload = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_RELATED,
                lambda: related.find_related(
                    conn,
                    binary_id=binary_id,
                    engine=engines.get_engine(),
                    limit=limit,
                    include_unrelated=include_unrelated,
                ),
            )
        except ValueError as exc:
            _fail(str(exc), json_output)
        except KeyError as exc:
            _fail(str(exc.args[0]), json_output)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(payload)))
        return
    _print_journal_action(log, json_output)
    _print_related(payload)


# ── composition ────────────────────────────────────────────────────

# Function rows the human table renders before it stops; the JSON payload
# carries the capped list the scan produced.
_COMPOSITION_ROWS_SHOWN = 50


def _print_composition_breakdown(title: str, rows: list[dict[str, Any]]) -> None:
    """Print one count/percent breakdown (name sources or quality bands)."""
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Label")
    table.add_column("Count", justify="right")
    table.add_column("Percent", justify="right")
    for row in rows:
        percent = row.get("percent")
        table.add_row(
            escape(str(row.get("label"))),
            str(row.get("count", 0)),
            "n/a" if percent is None else f"{percent}%",
        )
    console.print(table)


def _print_composition(payload: dict[str, Any]) -> None:
    """Print the headline counts, both breakdowns, the rollup and the rows."""
    total = int(payload["total_functions"])
    matched = int(payload["matched_functions"])
    percent = payload["matched_percent"]
    percent_text = "n/a" if percent is None else f"{percent}%"
    console.print(
        f"[bold cyan]{escape(str(payload['binary_name']))}[/bold cyan]"
        f" matched {matched} / {total} ({percent_text})"
    )
    console.print(f"refined: {'yes' if payload.get('refined') else 'no'}")
    _print_composition_breakdown("Function name sources", payload.get("name_sources", []))
    _print_composition_breakdown("Match quality", payload.get("match_quality", []))

    table = Table(title="Composition", show_header=True, header_style="bold")
    table.add_column("Binary")
    table.add_column("sha256")
    table.add_column("Functions", justify="right")
    table.add_column("Percent", justify="right")
    for row in payload.get("composition", []):
        row_percent = row.get("percent")
        table.add_row(
            escape(str(row.get("name"))),
            escape(str(row.get("sha256") or "n/a")),
            str(row.get("count", 0)),
            "n/a" if row_percent is None else f"{row_percent}%",
        )
    console.print(table)

    table = Table(title="Functions", show_header=True, header_style="bold")
    table.add_column("Function")
    table.add_column("VA")
    table.add_column("Size", justify="right")
    table.add_column("Band")
    table.add_column("Similarity", justify="right")
    table.add_column("Matched binary")
    rows = payload.get("functions", [])
    for row in rows[:_COMPOSITION_ROWS_SHOWN]:
        similarity = row.get("similarity")
        label = str(row.get("name") or "") or f"#{row['function_id']}"
        matched_name = row.get("matched_binary_name")
        table.add_row(
            escape(label),
            _as_hex(row.get("va")),
            str(row.get("size", 0)),
            escape(str(row.get("band"))),
            "n/a" if similarity is None else f"{similarity:.1f}",
            escape(str(matched_name)) if matched_name else "No match",
        )
    console.print(table)
    if len(rows) > _COMPOSITION_ROWS_SHOWN:
        console.print(f"[yellow]Showing {_COMPOSITION_ROWS_SHOWN} of {len(rows)} rows.[/yellow]")
    for note in payload.get("notes", []):
        console.print(f"[dim]{escape(str(note))}[/dim]")


@app.command("composition")
def composition_command(
    binary_id: int = typer.Argument(..., help="Binary id to summarise"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Summarize how the binary's functions match the rest of the corpus."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            log, payload = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_COMPOSITION,
                lambda: composition.run_composition(conn, binary_id=binary_id),
            )
        except KeyError as exc:
            _fail(str(exc.args[0]), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(payload)))
        return
    _print_journal_action(log, json_output)
    _print_composition(payload)


# ── add-binary ─────────────────────────────────────────────────────


@app.command("add-binary")
def add_binary(
    path: Path = typer.Argument(..., help="Path to the binary to register"),
    name: str | None = typer.Option(None, "--name", help="Display name (default: file name)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Register a binary by content hash (reportal's equivalent of an upload)."""
    binary = path.expanduser().resolve()
    if not binary.is_file():
        _fail(f"not a file: {path}", json_output)
    sha256 = _sha256_file(binary)
    display_name = name or binary.name
    portal_db = _db_path(json_output)
    store.init_db(portal_db)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            known = store.find_binary_by_sha256(conn, sha256) is not None
            binary_id = store.add_binary(
                conn,
                sha256=sha256,
                name=display_name,
                path=str(binary),
                size=binary.stat().st_size,
                fmt=binary.suffix.lstrip(".").upper(),
            )
            if not known:
                log.record(
                    effects.EFFECT_ROW_DELETE,
                    f"registered binary {binary_id}",
                    journal.row_delete_descriptor("binaries", binary_id),
                )
        payload = log.attach(
            {
                "binary_id": binary_id,
                "name": display_name,
                "sha256": sha256,
                "path": str(binary),
            }
        )
    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(f"[green]Registered[/green] binary {binary_id}: {display_name}")
        console.print(f"  path:   {binary}")
        console.print(f"  sha256: {sha256}")
    _print_journal_action(log, json_output)


# ── download ───────────────────────────────────────────────────────


def _write_protected_zip(source: Path, target: Path, member: str, password: str) -> int:
    """Write *source* as an encrypted zip at *target*, returning the bytes written.

    Like :func:`_copy_stream` the archive lands in a temporary file beside the
    target and is moved into place with ``os.replace``, so a failure leaves no
    half-written archive behind.
    """
    handle, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".download-zip-")
    os.close(handle)
    temp = Path(temp_name)
    try:
        with source.open("rb") as reader, temp.open("wb") as writer:
            written = zipcrypto.write_protected_zip(writer, member, reader, password)
        os.replace(temp, target)
        return written
    finally:
        with contextlib.suppress(OSError):
            temp.unlink()


def _copy_stream(source: Path, target: Path) -> int:
    """Copy *source* onto *target* in bounded chunks, returning the bytes written.

    The bytes land in a temporary file beside the target and are moved into
    place with ``os.replace``, so a copy that fails (a full disk, an interrupt)
    leaves no half-written target behind.
    """
    from reportal import api

    handle, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".download-")
    temp = Path(temp_name)
    written = 0
    try:
        with source.open("rb") as src, os.fdopen(handle, "wb") as dst:
            while True:
                chunk = src.read(api.BINARY_DOWNLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                dst.write(chunk)
                written += len(chunk)
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return written


@app.command("download")
def download(
    binary_id: int = typer.Argument(..., help="Binary id whose stored bytes to write"),
    analysis: bool = typer.Option(
        False, "--analysis", help="The id is an analysis id; write its binary's bytes"
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Target path (default: the stored name in the current directory)",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing target"),
    as_zip: bool = typer.Option(
        False, "--zip", help="Write a zip whose member is password protected instead"
    ),
    password: str = typer.Option(
        zipcrypto.DEFAULT_PASSWORD, "--password", help="Password for --zip"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Write a stored binary's bytes to a path, byte for byte.

    The bytes are copied in bounded chunks rather than read whole, since an
    upload may be up to the API's 256 MiB cap; the file name is the stored
    name, sanitized the same way the download route's header is.  ``--zip``
    writes a password-protected archive instead, the form a mail gateway or an
    upload form accepts; the password is a shared convention rather than a
    secret (ZipCrypto authenticates nothing).  ``--analysis`` resolves the id as
    an analysis id first, which is the local form of the hosted
    ``analyses/<id>/bytes`` read.
    """
    from reportal import api

    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    analysis_id = binary_id if analysis else None
    with contextlib.closing(store.connect(portal_db)) as conn:
        if analysis_id is not None:
            row = store.get_analysis(conn, analysis_id)
            if row is None:
                _fail(f"no analysis with id {analysis_id}", json_output)
            binary_id = int(row["binary_id"])
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        source = Path(str(binary["path"]))
        if not source.is_file():
            _fail(f"binary {binary_id} has no file at {binary['path']!r}", json_output)
        stored_name = api.download_filename(binary)
        target = (
            output if output is not None else Path(f"{stored_name}.zip" if as_zip else stored_name)
        ).expanduser()
        if target.exists() and not force:
            _fail(f"refusing to overwrite {target} without --force", json_output)
        if as_zip and (not password or len(password) > api.ZIP_PASSWORD_MAX_CHARS):
            _fail(f"the password must be 1 to {api.ZIP_PASSWORD_MAX_CHARS} characters", json_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        if as_zip:
            written = _write_protected_zip(source, target, f"{stored_name}.zip", password)
        else:
            written = _copy_stream(source, target)
        payload = {
            "binary_id": binary_id,
            "name": str(binary["name"]),
            "sha256": str(binary["sha256"]),
            "path": str(target),
            "bytes": written,
        }
        if as_zip:
            # The password is a shared convention, so echoing it is not a leak.
            payload["zip"] = True
            payload["member"] = f"{stored_name}.zip"
            payload["password"] = password
        if analysis_id is not None:
            payload["analysis_id"] = analysis_id
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if as_zip:
        console.print(
            f"[green]Wrote[/green] {written} bytes to {target}"
            f" (zip member {stored_name}.zip, password {password!r})"
        )
    else:
        console.print(f"[green]Wrote[/green] {written} bytes to {target}")


# ── firmware ───────────────────────────────────────────────────────


@app.command()
def firmware(
    binary_id: int = typer.Argument(..., help="Stored firmware image to carve"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Carve a stored firmware image: its embedded regions and their entropy.

    Pure byte work: reportal reads no filesystem inode table, runs nothing and
    stores the pass as the binary's `firmware` scan.
    """
    from reportal import api

    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = api.firmware_carve_binary(conn, binary_id)
        except api.ExtractError as exc:
            _fail(f"{exc.code}: {exc.detail}", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"\n[bold cyan]{payload['region_count']} region(s)[/bold cyan] in {payload['size']} bytes"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Index", justify="right")
    table.add_column("Offset", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Kind")
    table.add_column("Entropy", justify="right")
    table.add_column("Confidence")
    for region in payload["regions"]:
        table.add_row(
            str(region["index"]),
            hex(int(region["offset"])),
            str(region["size"]),
            str(region["kind"]),
            str(region["entropy"]),
            str(region["confidence"]),
        )
    console.print(table)
    console.print(f"[dim]{payload['note']}[/dim]")


@app.command("firmware-extract")
def firmware_extract(
    binary_id: int = typer.Argument(..., help="Stored firmware image whose regions to extract"),
    region: list[int] = typer.Option(None, "--region", help="Region index to carve (repeatable)"),
    collection_id: int = typer.Option(
        0, "--collection", help="Collection the carved binaries join (default: one per firmware)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Carve the stored firmware's regions out and register what they hold.

    A gzip, tar or zip region is unpacked with the archive reader; every other
    region is stored as a binary of its own.  The whole request is one journal
    action.
    """
    from reportal import api

    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = api.firmware_extract_binary(
                conn,
                binary_id,
                region_indexes=list(region) if region else None,
                collection_id=collection_id,
            )
        except api.ExtractError as exc:
            _fail(f"{exc.code}: {exc.detail}", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[green]Carved[/green] {len(payload['regions'])} region(s) into collection"
        f" {payload['collection_id']} ({payload['kept']} kept, {payload['skipped']} skipped)"
    )
    for member in payload["members"]:
        state = member["skipped"] or f"binary {member['binary_id']}"
        console.print(
            f"  region {member['region']} ({member['kind']}): {member['name']} -> {state}"
        )


# ── extract ────────────────────────────────────────────────────────


@app.command()
def extract(
    binary_id: int = typer.Argument(..., help="Stored binary id of the archive"),
    password: str = typer.Option("", "--password", help="Archive password, when it is encrypted"),
    collection_id: int = typer.Option(
        0, "--collection", help="Collection id to add the members to (default: a new one)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Unpack a stored archive and register the binaries it holds.

    Uses the same extraction the API and MCP do, so an unsupported format, a
    missing password, or a member that escapes the extraction root is refused
    with the same reason.  The whole command is one journal action.
    """
    from reportal import api

    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            payload = api.extract_archive_binary(
                conn, binary_id, password=password, collection_id=collection_id
            )
        except api.ExtractError as exc:
            _fail(exc.detail, json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Member", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Binary", justify="right")
    table.add_column("Note")
    for member in payload["members"]:
        identifier = str(member["binary_id"]) if member["binary_id"] is not None else "-"
        note = str(member["skipped"]) or ("duplicate" if member["duplicate"] else "")
        table.add_row(str(member["name"]), str(member["size"]), identifier, note)
    console.print(table)
    console.print(
        f"[green]Extracted[/green] {payload['kept']} of {len(payload['members'])} member(s)"
        f" into collection {payload['collection_id']} ({payload['collection_name']})"
    )
    for note in payload["notes"]:
        console.print(f"  [dim]{escape(str(note))}[/dim]")
    action = payload.get("journal_action")
    if action:
        console.print(f"[dim]journal action {action}[/dim]")


# ── enrich ─────────────────────────────────────────────────────────


@app.command()
def enrich(
    binary_id: int = typer.Argument(..., help="Binary id to fingerprint"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compute and store a binary fingerprint through the rebrew engine."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(
            f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            fingerprint = engine.fingerprint(path)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="binary_fingerprints",
                where="binary_id = ?",
                params=(binary_id,),
                description=f"replaced the fingerprint of binary {binary_id}",
            )
            store.set_fingerprint(conn, binary_id, fingerprint)
            if not before:
                journal.journaled_create(
                    log,
                    table="binary_fingerprints",
                    key={"binary_id": binary_id},
                    description=f"stored the fingerprint of binary {binary_id}",
                )

    if json_output:
        typer.echo(json.dumps(log.attach(fingerprint)))
        return
    _print_journal_action(log, json_output)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for field in _FINGERPRINT_FIELDS:
        if field in fingerprint:
            table.add_row(field, str(fingerprint[field]))
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    console.print(table)


# ── match ──────────────────────────────────────────────────────────


@app.command()
def match(
    binary_id: int = typer.Argument(..., help="Binary id whose functions to match"),
    min_similarity: float = typer.Option(
        matching.DEFAULT_MIN_SIMILARITY,
        "--min-similarity",
        help="Minimum similarity percent for a candidate",
    ),
    min_confidence: float = typer.Option(
        matching.DEFAULT_MIN_CONFIDENCE,
        "--min-confidence",
        help="Minimum softmax confidence for a candidate",
    ),
    top: int = typer.Option(
        matching.DEFAULT_TOP, "--top", min=1, help="Maximum candidates per function"
    ),
    include_self: bool = typer.Option(
        matching.DEFAULT_INCLUDE_SELF,
        "--self/--no-self",
        help="Allow the binary's own functions as candidates",
    ),
    platform: list[str] | None = typer.Option(
        None, "--platform", help="Restrict to a platform (repeatable)"
    ),
    architecture: list[str] | None = typer.Option(
        None, "--arch", help="Restrict to an architecture (repeatable)"
    ),
    binary: list[int] | None = typer.Option(
        None, "--binary", help="Restrict candidates to a binary id (repeatable)"
    ),
    collection: list[int] | None = typer.Option(
        None, "--collection", help="Restrict candidates to a collection id (repeatable)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rank each function of a binary against the local corpus under Match Settings.

    The platform and architecture scope is best-effort: it compares a binary's
    stored fingerprint when it has one, else its suffix-derived format/arch
    columns, so it is a coarse filter and not a guarantee.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    try:
        settings = matching.MatchSettings.from_request(
            {
                "min_similarity": min_similarity,
                "min_confidence": min_confidence,
                "top": top,
                "include_self": include_self,
                "platforms": list(platform or []),
                "architectures": list(architecture or []),
                "binary_ids": list(binary or []),
                "collection_ids": list(collection or []),
            }
        )
    except matching.InvalidSettingsError as exc:
        _fail(exc.detail, json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        if store.get_rebrew_context(conn, binary_id) is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="matches",
                where=_BINARY_MATCHES_WHERE,
                params=(binary_id,),
                description=f"replaced the matches of binary {binary_id}",
            )
            try:
                summary = matching.match_binary(
                    conn, binary_id=binary_id, engine=engine, settings=settings
                )
            except matching.InvalidSettingsError as exc:
                _fail(exc.detail, json_output)
            except similarity.SimilarityUnavailable:
                _fail(
                    "function matching requires the optional 'similarity' extra"
                    " (uv sync --extra similarity)",
                    json_output,
                )
            journal.journaled_new_rows(
                conn,
                log,
                table="matches",
                where=_BINARY_MATCHES_WHERE,
                params=(binary_id,),
                before=before,
                key=("id",),
                description=f"recorded a match of binary {binary_id}",
            )
            rows = matching.binary_match_rows(conn, binary_id)[:MAX_REPORT_ROWS]

    if json_output:
        typer.echo(
            json.dumps(
                log.attach(
                    {
                        "binary_id": binary_id,
                        **summary,
                        "settings": settings.payload(),
                        "notes": matching.scope_notes(settings),
                        "matches": rows,
                    }
                )
            )
        )
        return
    _print_journal_action(log, json_output)
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    console.print(
        f"matched {summary['matched']}/{summary['functions']} functions,"
        f" {summary['pairs']} candidate pairs"
    )
    for note in matching.scope_notes(settings):
        console.print(f"[yellow]{note}[/yellow]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Function", style="cyan")
    table.add_column("Candidate")
    table.add_column("Sim", justify="right")
    table.add_column("Conf", justify="right")
    for row in rows:
        table.add_row(
            f"{row['source_name']} @ 0x{row['source_va']:x}",
            f"{row['candidate_name']} @ 0x{row['candidate_va']:x}",
            f"{row['similarity']:.1f}",
            f"{row['confidence']:.2f}",
        )
    console.print(table)


# ── decompile ──────────────────────────────────────────────────────


@app.command()
def decompile(
    function_id: int = typer.Argument(..., help="Function id to decompile"),
    backend: str = typer.Option(
        engines.DEFAULT_DECOMPILER_BACKEND,
        "--backend",
        help="Decompiler backend: auto, kuna, r2ghidra, r2dec or ghidra",
    ),
    named: bool = typer.Option(False, "--named", help="Apply known symbol names"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Decompile one function through the rebrew engine and store the source."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if backend not in engines.DECOMPILER_BACKENDS:
        _fail(f"unknown decompiler backend: {backend}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            _fail(f"no function with id {function_id}", json_output)
        binary_id = int(function["binary_id"])
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        va = int(function["va"])
        try:
            result = engine.decompile(project_dir, va, backend, named)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        code = str(result.get("code") or "")
        resolved = str(result.get("backend") or backend)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"replaced the decompilation of function {function_id}",
            )
            store.set_decompilation(conn, function_id, code, resolved)
            if not before:
                journal.journaled_create(
                    log,
                    table="decompilations",
                    key={"function_id": function_id},
                    description=f"stored the decompilation of function {function_id}",
                )

    if json_output:
        typer.echo(
            json.dumps(log.attach({"va": va, "backend": resolved, "named": named, "code": code}))
        )
        return
    _print_journal_action(log, json_output)
    console.print(f"\n[bold cyan]function {function_id} @ 0x{va:x}[/bold cyan]")
    console.print(f"backend: {resolved}\n")
    console.print(code, markup=False)


# ── AI artifacts ───────────────────────────────────────────────────


def _run_ai_artifact(function_id: int, kind: str, json_output: bool) -> None:
    """Compute one AI artifact for a function through the configured LLM and store it.

    The model's input is the function's stored decompilation; the command never
    generates one.  An endpoint must be configured: without one the command
    fails with the same message the AI routes answer 503 with.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    client = llm.get_client()
    if not client.available():
        _fail(f"llm-unavailable: {llm.UNAVAILABLE_DETAIL}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        stored = store.get_decompilation(conn, function_id)
        if stored is None:
            _fail(
                f"function {function_id} has no stored decompilation"
                f" (run 'reportal decompile {function_id}')",
                json_output,
            )
        try:
            payload = llm.AI_RUNNERS[kind](str(stored["code"]), client=client)
        except llm.LlmUnavailable:
            _fail(f"llm-unavailable: {llm.UNAVAILABLE_DETAIL}", json_output)
        except llm.LlmError as exc:
            _fail(f"llm-error: {exc}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, kind),
                description=f"replaced the {kind} artifact of function {function_id}",
            )
            store.set_ai_artifact(conn, function_id, kind, payload, client.model)
            if not before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": kind},
                    description=f"stored the {kind} artifact of function {function_id}",
                )

    if json_output:
        typer.echo(
            json.dumps(
                log.attach(
                    {
                        "function_id": function_id,
                        "kind": kind,
                        "payload": payload,
                        "model": client.model,
                    }
                )
            )
        )
        return
    _print_journal_action(log, json_output)
    label = _AI_KIND_LABELS.get(kind, kind)
    console.print(
        f"\n[bold cyan]function {function_id}[/bold cyan] ({label}, model {client.model})"
    )
    _print_ai_payload(kind, payload)


def _print_ai_payload(kind: str, payload: dict[str, Any]) -> None:
    """Render one normalized AI artifact payload for the terminal."""
    if kind == llm.AI_KIND_SUMMARY:
        console.print(str(payload.get("summary", "")), markup=False)
        return
    if kind == llm.AI_KIND_COMMENTS:
        entries = payload.get("comments")
        entries = entries if isinstance(entries, list) else []
        if not entries:
            console.print("[yellow]No inline comments.[/yellow]")
            return
        table = Table(show_header=True, header_style="bold")
        table.add_column("Line", justify="right", style="magenta")
        table.add_column("Comment")
        for entry in entries:
            table.add_row(str(entry.get("line", "")), str(entry.get("comment", "")))
        console.print(table)
        return
    suggestions = payload.get("suggestions")
    suggestions = suggestions if isinstance(suggestions, list) else []
    if not suggestions:
        console.print("[yellow]No type suggestions.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Kind")
    table.add_column("Type", style="magenta")
    table.add_column("Confidence", justify="right")
    for entry in suggestions:
        table.add_row(
            str(entry.get("name", "")),
            str(entry.get("kind", "")),
            str(entry.get("type", "")),
            f"{float(entry.get('confidence', 0.0)):.2f}",
        )
    console.print(table)


@app.command()
def summary(
    function_id: int = typer.Argument(..., help="Function id whose decompilation to summarize"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Summarize a function's stored decompilation with the configured LLM."""
    _run_ai_artifact(function_id, llm.AI_KIND_SUMMARY, json_output)


@app.command("ai-comments")
def ai_comments(
    function_id: int = typer.Argument(..., help="Function id whose decompilation to comment"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Write inline comments for a function's stored decompilation."""
    _run_ai_artifact(function_id, llm.AI_KIND_COMMENTS, json_output)


@app.command("suggest-types")
def suggest_types(
    function_id: int = typer.Argument(..., help="Function id whose types to suggest"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Suggest parameter, return and local types for a stored decompilation."""
    _run_ai_artifact(function_id, llm.AI_KIND_TYPES, json_output)


# ── AI identifier renames ──────────────────────────────────────────


def _print_rename_suggestions(suggestions: list[dict[str, Any]]) -> None:
    """Render rename suggestions as a table."""
    if not suggestions:
        console.print("[yellow]No rename suggestions.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("From", style="cyan")
    table.add_column("To", style="green")
    table.add_column("Kind")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason")
    for suggestion in suggestions:
        table.add_row(
            str(suggestion.get("from", "")),
            str(suggestion.get("to", "")),
            str(suggestion.get("kind", "")),
            f"{float(suggestion.get('confidence', 0.0)):.2f}",
            str(suggestion.get("reason", "")),
        )
    console.print(table)


@app.command("suggest-renames")
def suggest_renames(
    function_id: int = typer.Argument(..., help="Function id whose identifiers to rename"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Suggest identifier renames for a function's stored decompilation."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    client = llm.get_client()
    if not client.available():
        _fail(f"llm-unavailable: {llm.UNAVAILABLE_DETAIL}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_KIND),
                description=f"replaced the renames artifact of function {function_id}",
            )
            try:
                result = renames.suggest_renames(conn, function_id=function_id, client=client)
            except renames.NoDecompilationError:
                _fail(
                    f"function {function_id} has no stored decompilation"
                    f" (run 'reportal decompile {function_id}')",
                    json_output,
                )
            except llm.LlmError as exc:
                _fail(f"llm-error: {exc}", json_output)
            if not before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_KIND},
                    description=f"stored the renames artifact of function {function_id}",
                )

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"\n[bold cyan]function {function_id}[/bold cyan]"
        f" ({result['count']} rename suggestions, model {result['model']})"
    )
    _print_rename_suggestions(result["suggestions"])


@app.command("apply-renames")
def apply_renames(
    function_id: int = typer.Argument(..., help="Function id whose decompilation to rename"),
    apply_all: bool = typer.Option(False, "--all", help="Apply every stored suggestion"),
    from_name: str | None = typer.Option(None, "--from", help="Identifier to rename"),
    to_name: str | None = typer.Option(None, "--to", help="New name for the identifier"),
    rename_function: bool = typer.Option(
        False,
        "--rename-function",
        help="Also rename the function row (a --from/--to pair names the function itself)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Apply rename suggestions to a function's stored decompilation."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if apply_all and (from_name is not None or to_name is not None):
        _fail("--all cannot be combined with --from/--to", json_output)
    if (from_name is None) != (to_name is None):
        _fail("--from and --to must be given together", json_output)
    applied: list[dict[str, Any]] | None = None
    if from_name is not None and to_name is not None:
        entry: dict[str, Any] = {"from": from_name, "to": to_name}
        if rename_function:
            # --rename-function declares that this rename names the function, so
            # the entry carries the kind the apply's rename rule keys on.
            entry["kind"] = "function"
        applied = [entry]
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            artifact_before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_APPLIED_KIND),
                description=f"replaced the applied renames of function {function_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"rewrote the decompilation of function {function_id}",
            )
            try:
                result = journal.journaled_name_change(
                    conn,
                    log,
                    function_id,
                    lambda: renames.apply_renames(
                        conn,
                        function_id=function_id,
                        applied=applied,
                        actor="cli",
                        rename_function=rename_function,
                    ),
                )
            except renames.NoDecompilationError:
                _fail(
                    f"function {function_id} has no stored decompilation"
                    f" (run 'reportal decompile {function_id}')",
                    json_output,
                )
            except renames.NoSuggestionError:
                _fail(
                    f"function {function_id} has no stored rename suggestions"
                    f" (run 'reportal suggest-renames {function_id}')",
                    json_output,
                )
            if result["decompilation_updated"] and not artifact_before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_APPLIED_KIND},
                    description=f"journaled the applied renames of function {function_id}",
                )

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"\n[bold cyan]function {function_id}[/bold cyan]"
        f" ({len(result['applied'])} applied, {len(result['skipped'])} skipped)"
    )
    _print_rename_suggestions(result["applied"])
    for entry in result["skipped"]:
        console.print(
            f"[yellow]skipped[/yellow] {entry.get('from', '?')}: {entry.get('reason', '')}"
        )
    if result["decompilation_updated"]:
        console.print("[green]Stored decompilation updated.[/green]")


@app.command("revert-renames")
def revert_renames(
    function_id: int = typer.Argument(..., help="Function id whose decompilation to restore"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Restore the decompilation text the last apply renamed."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_APPLIED_KIND),
                description=f"reverted the applied renames of function {function_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"restored the decompilation of function {function_id}",
            )
            try:
                result = renames.revert_renames(conn, function_id=function_id)
            except renames.NoRevertError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Restored[/green] the decompilation of function {function_id}")


# ── AI decompilation pipeline ──────────────────────────────────────


# Status colors of the pipeline step lines, and of a revert entry's outcome.
_PIPELINE_STATUS_COLORS: dict[str, str] = {
    store.PIPELINE_STEP_DONE: "green",
    store.PIPELINE_STEP_SKIPPED: "yellow",
    store.PIPELINE_STEP_FAILED: "red",
    store.PIPELINE_STEP_DEACTIVATED: "magenta",
}


def _print_pipeline_run(run: dict[str, Any]) -> None:
    """Render one pipeline run: its steps, then the artifacts it produced."""
    function_id = int(run["function_id"])
    console.print(
        f"\n[bold cyan]function {function_id}[/bold cyan]"
        f" (run {run['id']}, {run['status']}, model {run['model'] or 'none'})"
    )
    for step in run["steps"]:
        status = str(step["status"])
        color = _PIPELINE_STATUS_COLORS.get(status, "white")
        line = f"  {step['name']}  [{color}]{status}[/{color}]  {int(step['duration_ms'])} ms"
        if step["reason"]:
            line += f"  {step['reason']}"
        console.print(line)
    artifacts = run.get("artifacts") or {}
    predicted = artifacts.get("predicted_name")
    confidence = predicted.get("confidence") if isinstance(predicted, dict) else None
    name = predicted.get("name") if isinstance(predicted, dict) else None
    source = predicted.get("source") if isinstance(predicted, dict) else ""
    console.print(
        f"predicted name: {name or 'none'}"
        + (f" ({source}, confidence {float(cast(float, confidence)):.2f})" if name else "")
    )
    summary = artifacts.get("summary")
    if isinstance(summary, dict) and summary.get("summary"):
        console.print(str(summary["summary"]), markup=False)
    console.print(f"comment count: {_comment_count(artifacts)}")


def _comment_count(artifacts: dict[str, Any]) -> int:
    """Number of inline comments the run's stored artifact carries."""
    comments = artifacts.get("inline_comments")
    entries = comments.get("comments") if isinstance(comments, dict) else None
    return len(entries) if isinstance(entries, list) else 0


@app.command("pipeline")
def pipeline_command(
    function_id: int = typer.Argument(..., help="Function id to run the pipeline over"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Run the AI decompilation pipeline over one function and store the run."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            run = pipeline.run_pipeline(conn, function_id=function_id)
        except KeyError:
            _fail(f"no function with id {function_id}", json_output)
        except pipeline.PipelineUnavailable as exc:
            _fail(f"pipeline-unavailable: {exc}", json_output)

    if json_output:
        typer.echo(json.dumps(run))
        return
    _print_pipeline_run(run)


@app.command("pipeline-revert")
def pipeline_revert(
    run_id: int = typer.Argument(..., help="Pipeline run id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Undo the writes one stored pipeline run journaled."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            result = pipeline.revert_run(conn, run_id)
        except KeyError:
            _fail(f"no pipeline run with id {run_id}", json_output)

    if json_output:
        typer.echo(json.dumps(result))
        return
    console.print(f"\n[bold cyan]run {run_id}[/bold cyan]")
    undone = result["reverted"]
    if not undone:
        console.print("[yellow]Nothing to revert.[/yellow]")
        return
    for entry in undone:
        color = _PIPELINE_STATUS_COLORS.get(str(entry["status"]), "white")
        console.print(f"  [{color}]{entry['status']}[/{color}]  {entry['description']}")


# ── Components ─────────────────────────────────────────────────────


@app.command("components")
def components_command(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the registered pipeline components with their origins."""
    rows: list[dict[str, Any]] = [
        {
            "name": entry.component.name,
            "requires": sorted(entry.component.requires),
            "provides": sorted(entry.component.provides),
            "origin": entry.origin,
            "reloadable": entry.reloadable,
        }
        for entry in components.registrations()
    ]
    if json_output:
        typer.echo(json.dumps(rows))
        return
    table = Table(title="Components")
    for column in ("name", "requires", "provides", "origin", "reloadable"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            row["name"],
            ", ".join(row["requires"]) or "none",
            ", ".join(row["provides"]) or "none",
            row["origin"],
            "yes" if row["reloadable"] else "no",
        )
    console.print(table)


@app.command("integrations")
def integrations_command(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List every plugin seam and the parts its registry currently holds."""
    payload = integrations.inventory()
    if json_output:
        typer.echo(json.dumps(payload))
        return
    for seam in payload["seams"]:
        table = Table(title=f"{seam['name']} ({seam['group']})")
        for column in ("name", "detail", "origin"):
            table.add_column(column)
        for part in seam["parts"]:
            table.add_row(part["name"], part["detail"], part["origin"] or "-")
        console.print(table)
    console.print(f"[bold]{payload['count']}[/bold] seams")


@app.command("components-reload")
def components_reload_command(
    name: str | None = typer.Argument(None, help="Component to reload; omit with --all"),
    all_components: bool = typer.Option(False, "--all", help="Reload every reloadable component"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Reload one component's implementation, or every reloadable one."""
    if all_components:
        try:
            report = components.reload_all()
        except components.ComponentMissingError as exc:
            _fail(f"component-missing: {exc}", json_output)
        if json_output:
            typer.echo(json.dumps(report))
            return
        console.print(
            f"\n[bold cyan]reloaded {report['count']}[/bold cyan]"
            f"  changed {len(report['changed'])}  skipped {len(report['skipped'])}"
        )
        for entry in report["reloaded"]:
            state = "changed" if entry["changed"] else "unchanged"
            console.print(f"  [green]{entry['name']}[/green]  {state}  {entry['new_origin']}")
        for entry in report["skipped"]:
            console.print(f"  [yellow]{entry['name']}[/yellow]  skipped: {entry['reason']}")
        return
    if not name:
        _fail("provide a component name or --all", json_output)
    try:
        result = components.reload_component(name)
    except KeyError:
        _fail(f"no component named {name}", json_output)
    except components.NotReloadableError as exc:
        _fail(f"not-reloadable: {exc}", json_output)
    except components.ComponentMissingError as exc:
        _fail(f"component-missing: {exc}", json_output)
    if json_output:
        typer.echo(json.dumps(result))
        return
    state = "changed" if result["changed"] else "unchanged"
    console.print(
        f"\n[bold cyan]{result['name']}[/bold cyan]  {state}  [green]reloaded[/green]"
        f"  {result['old_origin']} -> {result['new_origin']}"
    )


@app.command("components-deactivate")
def components_deactivate_command(
    name: str | None = typer.Argument(None, help="Component to withdraw from the live composition"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Withdraw one component's contribution, running its revert where declared."""
    if not name:
        _fail("provide a component name", json_output)
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            result = pipeline.withdraw_component(conn, name)
        except KeyError:
            _fail(f"no component named {name}", json_output)
        except pipeline.NotWithdrawableError as exc:
            _fail(f"not-withdrawable: {exc}", json_output)
    if json_output:
        typer.echo(json.dumps(result))
        return
    console.print(f"\n[bold cyan]{result['name']}[/bold cyan]  [green]withdrawn[/green]")
    for entry in result["deactivated"]:
        reverted = entry["reverted"]
        state = "reverted" if reverted else "no revert" if reverted is None else "revert failed"
        console.print(f"  {entry['name']}  {state}")
    for change in result["context_changes"]:
        mark = "applied" if change["applied"] else "not applied"
        console.print(f"  {change['change']} {change['name']}  {mark}")
    if not result["journaled"]:
        console.print("[dim]no durable write to journal[/dim]")


# ── Auto mode ──────────────────────────────────────────────────────

# Colors of the auto task status lines.
_AUTO_TASK_COLORS: dict[str, str] = {
    store.PIPELINE_STEP_DONE: "green",
    auto_store.AUTO_TASK_FAILED: "red",
    auto_store.AUTO_TASK_SKIPPED: "yellow",
    auto_store.AUTO_TASK_RUNNING: "cyan",
}


def _print_auto_run(run: dict[str, Any]) -> None:
    """Render one auto run: its coverage delta, then its task tree."""
    before = run.get("coverage_before") or {}
    after = run.get("coverage_after") or {}
    console.print(
        f"\n[bold cyan]auto run {run['run_id']}[/bold cyan]"
        f" (binary {run['binary_id']}, {run['status']}, worker {run['worker'] or 'none'})"
    )
    console.print(
        f"  coverage {before.get('matched', 0)}/{before.get('total', 0)}"
        f" -> {after.get('matched', 0)}/{after.get('total', 0)}"
        f"  matched {run['matched']}  improved {run['improved']}"
        f"  failed {run['failed']}  skipped {run['skipped']}"
        f"  tasks {run['tasks']}  attempts {run['attempts']}"
    )
    for node in run["tree"]:
        _print_auto_task(node, 1)


def _print_auto_task(node: dict[str, Any], depth: int) -> None:
    """Render one auto task and its children, indented by depth."""
    status = str(node["status"])
    color = _AUTO_TASK_COLORS.get(status, "white")
    line = (
        f"  {'  ' * depth}[{color}]{status}[/{color}]"
        f"  {node['kind']}  {node['title']}  attempts {node['attempts']}"
    )
    if node["worker"]:
        line += f"  worker {node['worker']}"
    console.print(line)
    for child in node.get("children", []):
        _print_auto_task(child, depth + 1)


def _recover_latest_stale_run(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Recover a binary's latest run when it is stale; None when there is none."""
    latest = auto_store.latest_auto_run(conn, binary_id)
    if latest is None or latest["status"] != auto_store.AUTO_RUN_RUNNING:
        return None
    return auto_mode.recover_auto_run(conn, int(latest["id"]))


@app.command("auto")
def auto_command(
    binary_id: int = typer.Argument(..., help="Binary id to work on"),
    worker: str = typer.Option(
        auto_workers.WORKER_OFFLINE, "--worker", help="Worker name to run each batch with"
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Write candidate C files into the rebrew project and compile them",
    ),
    concurrency: int = typer.Option(
        auto_mode.DEFAULT_CONCURRENCY, "--concurrency", help="Maximum live worker calls"
    ),
    functions_per_task: int = typer.Option(
        auto_mode.DEFAULT_FUNCTIONS_PER_TASK,
        "--functions-per-task",
        help="Functions per leaf batch",
    ),
    max_attempts: int = typer.Option(
        auto_mode.DEFAULT_MAX_ATTEMPTS, "--max-attempts", help="Attempts per function"
    ),
    max_tasks: int = typer.Option(
        auto_mode.DEFAULT_MAX_TASKS, "--max-tasks", help="Maximum task rows the run creates"
    ),
    recover: bool = typer.Option(
        False,
        "--recover",
        help="Recover the binary's latest stale run before starting a new one",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Decompose a binary's outstanding functions and work them with a worker.

    A dry run by default: nothing is compiled, no file is written into the
    rebrew project and no function status changes.  ``--recover`` closes the
    binary's latest run when a dead process left it `running`, merging the
    writes its unfinished tasks recorded into that run's undo plan first.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if execute:
        console.print(
            "[bold yellow]--execute writes candidate C files into the rebrew"
            " project's reversed source directory and compiles them[/bold yellow]"
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        recovered: dict[str, Any] | None = None
        if recover:
            recovered = _recover_latest_stale_run(conn, binary_id)
        try:
            run = auto_mode.run_auto(
                conn,
                binary_id=binary_id,
                worker=worker,
                execute=execute,
                concurrency=concurrency,
                functions_per_task=functions_per_task,
                max_attempts=max_attempts,
                max_tasks=max_tasks,
            )
        except ValueError as exc:
            _fail(str(exc), json_output)
        except KeyError:
            _fail(f"no binary with id {binary_id}", json_output)
        if recovered is not None:
            run = {**run, "recovered": recovered}

    if json_output:
        typer.echo(json.dumps(run))
        return
    if recovered is not None:
        console.print(
            f"[yellow]recovered stale run {recovered['run_id']}:"
            f" {recovered['recovered_tasks']} task(s) interrupted,"
            f" {recovered['added_descriptors']} descriptor(s) added,"
            f" status {recovered['status']}[/yellow]"
        )
    _print_auto_run(run)


@app.command("auto-revert")
def auto_revert(
    run_id: int = typer.Argument(..., help="Auto run id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove the files one stored auto run wrote and delete its rows."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            result = auto_mode.revert_auto_run(conn, run_id)
        except KeyError:
            _fail(f"no auto run with id {run_id}", json_output)

    if json_output:
        typer.echo(json.dumps(result))
        return
    console.print(f"\n[bold cyan]run {run_id}[/bold cyan]")
    removed = result["removed"]
    if not removed and not result["restored"]:
        console.print("[yellow]Nothing to revert.[/yellow]")
        return
    for entry in removed:
        color = "green" if entry["status"] == "removed" else "yellow"
        console.print(f"  [{color}]{entry['status']}[/{color}]  {entry['path']}")
    for entry in result["restored"]:
        console.print(
            f"  [green]restored[/green]  function {entry['function_id']} -> {entry['status']}"
        )


@app.command("auto-recover")
def auto_recover(
    run_id: int = typer.Argument(..., help="Auto run id to recover"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Close a run a dead process left `running`, keeping its recorded writes revertible."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            result = auto_mode.recover_auto_run(conn, run_id)
        except KeyError:
            _fail(f"no auto run with id {run_id}", json_output)

    if json_output:
        typer.echo(json.dumps(result))
        return
    console.print(
        f"\n[bold cyan]run {run_id}[/bold cyan]"
        f"  recovered {result['recovered_tasks']} task(s)"
        f"  {result['added_descriptors']} descriptor(s) added"
        f"  status {result['status']}"
    )


# ── conversations ──────────────────────────────────────────────────


@app.command("conversations")
def conversations_command(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List stored conversations."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        rows = store.list_conversations(conn)

    if json_output:
        typer.echo(json.dumps({"conversations": rows}))
        return
    if not rows:
        console.print("[yellow]No conversations.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", justify="right")
    table.add_column("Title", style="cyan")
    table.add_column("Scope")
    table.add_column("Messages", justify="right")
    table.add_column("Created", style="magenta")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["title"]),
            f"{row['scope_kind']} {row['scope_id']}",
            str(row["message_count"]),
            str(row["created_at"]),
        )
    console.print(table)


@app.command("chat-new")
def chat_new(
    function_id: int | None = typer.Option(
        None, "--function", help="Function id to scope the conversation to"
    ),
    binary_id: int | None = typer.Option(
        None, "--binary", help="Binary id to scope the conversation to"
    ),
    title: str | None = typer.Option(None, "--title", help="Conversation title"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Create a conversation scoped to one function or one binary."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if function_id is not None and binary_id is not None:
        _fail("provide exactly one of --function or --binary", json_output)
    if function_id is None and binary_id is None:
        _fail("provide exactly one of --function or --binary", json_output)
    scope_kind = (
        conversations.SCOPE_KIND_FUNCTION
        if function_id is not None
        else conversations.SCOPE_KIND_BINARY
    )
    scope_id = cast(int, function_id if function_id is not None else binary_id)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if scope_kind == conversations.SCOPE_KIND_FUNCTION:
            if store.get_function(conn, scope_id) is None:
                _fail(f"no function with id {scope_id}", json_output)
        elif store.get_binary(conn, scope_id) is None:
            _fail(f"no binary with id {scope_id}", json_output)
        resolved = (title or "").strip() or conversations.default_title(
            conn, scope_kind=scope_kind, scope_id=scope_id
        )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            conversation_id = store.create_conversation(
                conn, scope_kind=scope_kind, scope_id=scope_id, title=resolved
            )
            journal.journaled_create(
                log,
                table="conversations",
                key=conversation_id,
                description=f"created conversation {conversation_id}",
            )
            conversation = store.get_conversation(conn, conversation_id)

    if json_output:
        typer.echo(json.dumps(log.attach(conversation or {})))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Created[/green] conversation {conversation_id}:"
        f" {resolved} ({scope_kind} {scope_id})"
    )


@app.command()
def chat(
    conversation_id: int = typer.Argument(..., help="Conversation id to continue"),
    message: str = typer.Argument(..., help="Message to send"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Send one message to a conversation through the configured LLM."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    client = llm.get_client()
    if not client.available():
        _fail(f"llm-unavailable: {llm.UNAVAILABLE_DETAIL}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            _fail(f"no conversation with id {conversation_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = {int(row["id"]) for row in store.list_messages(conn, conversation_id)}
            try:
                result = conversations.send_message(
                    conn, conversation_id=conversation_id, content=message, client=client
                )
            except llm.LlmUnavailable:
                _fail(f"llm-unavailable: {llm.UNAVAILABLE_DETAIL}", json_output)
            except llm.LlmError as exc:
                _fail(f"llm-error: {exc}", json_output)
            journal.journaled_messages(conn, log, conversation_id, before)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print("[bold cyan]you[/bold cyan]")
    console.print(message, markup=False)
    console.print("[bold green]assistant[/bold green]")
    console.print(str(result["assistant"]["content"]), markup=False)


# ── knowledge ──────────────────────────────────────────────────────


def _snippet(text: str) -> str:
    """Return one line of *text*, truncated to :data:`MAX_SNIPPET_CHARS`."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= MAX_SNIPPET_CHARS:
        return collapsed
    return collapsed[: MAX_SNIPPET_CHARS - 1] + "…"


def _print_hits(results: list[dict[str, Any]]) -> None:
    """Print ranked knowledge hits: title, score, method, source and snippet."""
    if not results:
        console.print("[yellow]No matches.[/yellow]")
        return
    for rank, hit in enumerate(results, start=1):
        console.print(
            f"[bold cyan]{rank}. {hit['title']}[/bold cyan]"
            f"  [magenta]{hit['score']:.4f}[/magenta] ({hit['method']})"
        )
        console.print(f"   {hit['source']}", markup=False)
        console.print(f"   {_snippet(str(hit['text']))}", markup=False)


@app.command()
def ingest(
    binary_id: int = typer.Argument(..., help="Binary id to scope the document to"),
    path: Path = typer.Argument(..., help="Text file to ingest"),
    title: str | None = typer.Option(None, "--title", help="Document title (default: file name)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Ingest one local text file as a document of a binary's knowledge scope."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not path.is_file():
        _fail(f"no file at {path}", json_output)
    if not knowledge.is_supported_name(path.name):
        _fail(
            f"unsupported-format: {path.name} is not a supported text format"
            f" ({', '.join(sorted(knowledge.TEXT_EXTENSIONS))})",
            json_output,
        )
    if path.stat().st_size > knowledge.MAX_DOCUMENT_BYTES:
        _fail(
            f"file-too-large: {path} exceeds {knowledge.MAX_DOCUMENT_BYTES} bytes",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = knowledge.ingest_document(
                    conn,
                    scope_kind=knowledge.SCOPE_KIND_BINARY,
                    scope_id=binary_id,
                    title=title or path.name,
                    source=str(path),
                    mime="",
                    data=path.read_bytes(),
                )
            except knowledge.KnowledgeError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
            journal.journaled_ingest(conn, log, payload)
        payload = log.attach(payload)

    if json_output:
        typer.echo(json.dumps(payload))
    else:
        verb = "Already stored" if payload["duplicate"] else "Ingested"
        console.print(
            f"[green]{verb}[/green] document {payload['id']}: {payload['title']}"
            f" ({payload['chunk_count']} chunks, {payload['size']} bytes)"
        )
    _print_journal_action(log, json_output)


@app.command()
def ingest_url(
    binary_id: int = typer.Argument(..., help="Binary id to scope the document to"),
    url: str = typer.Argument(..., help="http(s) URL to fetch and ingest"),
    title: str | None = typer.Option(None, "--title", help="Document title (default: untitled)"),
    project: bool = typer.Option(
        False, "--project", help="Store in the project scope, ignoring the binary id"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Fetch one HTTP(S) URL into a knowledge scope; off by default.

    Remote ingestion needs ``REPORTAL_ALLOW_REMOTE_INGEST`` or the workspace
    ``[knowledge] allow_remote = true``; while it is disabled the command fails
    with the same ``remote-ingest-disabled`` message the API answers.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not remote_ingest.remote_enabled():
        _fail(f"{remote_ingest.ERROR_DISABLED}: {remote_ingest.DISABLED_DETAIL}", json_output)
    scope_kind = knowledge.SCOPE_KIND_PROJECT if project else knowledge.SCOPE_KIND_BINARY
    scope_id = 0 if project else binary_id
    with contextlib.closing(store.connect(portal_db)) as conn:
        if not project and store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = remote_ingest.ingest_url(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    url=url,
                    title=title,
                )
            except remote_ingest.RemoteIngestError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
            except knowledge.KnowledgeError as exc:
                _fail(f"{exc.code}: {exc.detail}", json_output)
            journal.journaled_ingest(conn, log, payload)
        payload = log.attach(payload)

    if json_output:
        typer.echo(json.dumps(payload))
    else:
        verb = "Already stored" if payload["duplicate"] else "Ingested"
        console.print(
            f"[green]{verb}[/green] document {payload['id']}: {payload['title']}"
            f" ({payload['chunk_count']} chunks, {payload['size']} bytes)"
        )
    _print_journal_action(log, json_output)


@app.command()
def documents(
    binary_id: int = typer.Argument(..., help="Binary id whose documents to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the knowledge documents scoped to one binary."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        rows = store.list_documents(
            conn, scope_kind=knowledge.SCOPE_KIND_BINARY, scope_id=binary_id
        )

    if json_output:
        typer.echo(json.dumps({"documents": rows}))
        return
    if not rows:
        console.print("[yellow]No documents.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", justify="right")
    table.add_column("Title", style="cyan")
    table.add_column("Source")
    table.add_column("Size", justify="right")
    table.add_column("Chunks", justify="right")
    table.add_column("Created", style="magenta")
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["title"]),
            str(row["source"]),
            str(row["size"]),
            str(row["chunk_count"]),
            str(row["created_at"]),
        )
    console.print(table)


@app.command("knowledge")
def knowledge_command(
    binary_id: int = typer.Argument(..., help="Binary id whose documents to search"),
    query: str = typer.Argument(..., help="Search query"),
    limit: int = typer.Option(
        knowledge.DEFAULT_SEARCH_LIMIT, "--limit", min=1, help="Maximum results"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Search a binary's knowledge documents and print the ranked snippets."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        results = knowledge.search_knowledge(
            conn,
            query=query,
            scope_kind=knowledge.SCOPE_KIND_BINARY,
            scope_id=binary_id,
            limit=limit,
        )

    if json_output:
        typer.echo(json.dumps({"query": query, "count": len(results), "results": results}))
        return
    _print_hits(results)


@app.command("context")
def context_command(
    function_id: int = typer.Argument(..., help="Function id whose binary documents to search"),
    query: str | None = typer.Option(
        None, "--query", help="Search query (default: the function name)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Retrieve knowledge documents for a function from its binary's scope."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            _fail(f"no function with id {function_id}", json_output)
        resolved = (query or "").strip() or str(function["name"])
        results = knowledge.retrieve(
            conn,
            query=resolved,
            scope_kind=knowledge.SCOPE_KIND_BINARY,
            scope_id=int(function["binary_id"]),
        )

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "function_id": function_id,
                    "query": resolved,
                    "count": len(results),
                    "results": results,
                }
            )
        )
        return
    _print_hits(results)


# ── knowledge graph ────────────────────────────────────────────────


@app.command("graph-build")
def graph_build(
    binary_id: int = typer.Argument(..., help="Binary id whose graph to rebuild"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rebuild a binary's knowledge graph from the stored rows."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_graph_rebuild(
                conn, log, binary_id, lambda: graph.build_graph(conn, binary_id=binary_id)
            )

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Built[/green] graph for binary {binary_id}:"
        f" {result['nodes']} nodes, {result['edges']} edges"
    )
    if result["truncated"]:
        console.print("[yellow]Graph truncated at the node or edge cap.[/yellow]")


@app.command("graph")
def graph_command(
    binary_id: int = typer.Argument(..., help="Binary id whose graph to show"),
    node: str | None = typer.Option(None, "--node", help="Show one node and its neighbors"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show a binary's stored graph: node counts, or one node's neighbors.

    The whole stored graph is shown, document nodes included, since this is the
    local inspection command; the HTTP GET leaves them out by default.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    detail: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        if node is not None:
            try:
                detail = graph.neighbors(conn, node_id=node)
            except KeyError:
                _fail(f"no graph node {node}", json_output)
        else:
            if store.count_graph_nodes(conn, binary_id) == 0:
                _fail(
                    f"no graph for binary {binary_id} (run 'reportal graph-build {binary_id}')",
                    json_output,
                )
            payload = graph.graph_payload(conn, binary_id=binary_id, include_documents=True)

    if json_output:
        typer.echo(json.dumps(detail if detail is not None else payload))
        return
    if detail is not None:
        _print_graph_neighbors(detail)
        return
    assert payload is not None  # the branch above fills exactly one of the two
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Kind", style="cyan")
    table.add_column("Nodes", justify="right")
    for kind in graph.GRAPH_NODE_KINDS:
        table.add_row(kind, str(payload["counts"].get(kind, 0)))
    console.print(table)
    console.print(f"{len(payload['nodes'])} nodes, {len(payload['edges'])} edges")
    if payload["truncated"]:
        console.print("[yellow]Graph truncated at the node or edge cap.[/yellow]")


def _print_graph_neighbors(detail: dict[str, Any]) -> None:
    """Print one node and its incoming and outgoing neighbor groups."""
    node = detail["node"]
    console.print(f"\n[bold cyan]{node['label']}[/bold cyan] [magenta]{node['kind']}[/magenta]")
    console.print(str(node["id"]), markup=False)
    for direction, groups in (("incoming", detail["incoming"]), ("outgoing", detail["outgoing"])):
        if not groups:
            continue
        console.print(f"[bold]{direction}[/bold]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Relation", style="cyan")
        table.add_column("Kind")
        table.add_column("Label")
        table.add_column("Weight", justify="right")
        for rel, entries in groups.items():
            for entry in entries:
                weight = f"{entry['weight']:.4g}"
                table.add_row(rel, str(entry["kind"]), str(entry["label"]), weight)
        console.print(table)


# ── knowledge graph backends ───────────────────────────────────────


@app.command("graph-backends")
def graph_backends_command(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the registered knowledge-graph backends and their availability."""
    statuses = [backend.describe() for backend in graph_backends.graph_backends()]
    payload: dict[str, Any] = {
        "backends": statuses,
        "default": graph_backends.configured_backend_name(),
    }
    if json_output:
        typer.echo(json.dumps(payload))
        return
    table = Table(title="Graph backends")
    for column in ("name", "available", "query", "note"):
        table.add_column(column)
    for entry in statuses:
        note = entry["description"] if entry["available"] else entry["unavailable_reason"]
        table.add_row(
            entry["name"],
            "yes" if entry["available"] else "no",
            "yes" if entry["supports_query"] else "no",
            note,
        )
    console.print(table)
    console.print(f"default: {payload['default']}")


@app.command("graph-sync")
def graph_sync_command(
    binary_id: int = typer.Argument(..., help="Binary id whose graph to sync"),
    backend: str | None = typer.Option(
        None, "--backend", help="Backend name (default: the configured backend)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Hand a binary's stored graph to a backend and print its report."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        try:
            result = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name=backend)
        except graph_backends.UnknownBackendError as exc:
            _fail(str(exc), json_output)
        except graph_backends.GraphNotBuiltError as exc:
            _fail(str(exc), json_output)
        except graph_backends.BackendUnavailableError as exc:
            _fail(f"backend-unavailable: {exc}", json_output)

    if json_output:
        typer.echo(json.dumps(result))
        return
    console.print(
        f"[green]Synced[/green] binary {binary_id} to [bold]{result['backend']}[/bold]:"
        f" {result['nodes']} nodes, {result['edges']} edges"
        f" ({result['pushed_nodes']} pushed)"
    )


@app.command("graph-query")
def graph_query_command(
    query: str = typer.Argument(..., help="Node id or text to search for"),
    backend: str | None = typer.Option(
        None, "--backend", help="Backend name (default: the configured backend)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Query a graph backend that supports querying."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        try:
            selected = graph_backends.get_graph_backend(
                backend or graph_backends.configured_backend_name()
            )
        except graph_backends.UnknownBackendError as exc:
            _fail(str(exc), json_output)
        if not selected.available():
            _fail(
                f"backend-unavailable: {selected.name} is unavailable:"
                f" {selected.unavailable_reason()}",
                json_output,
            )
        if not graph_backends.backend_supports_query(selected):
            _fail(
                f"query-unsupported: backend {selected.name!r} does not support query", json_output
            )
        result = graph_backends.run_query(
            selected, conn, query=query, limit=graph_backends.DEFAULT_QUERY_LIMIT
        )

    if json_output:
        typer.echo(json.dumps(result))
        return
    results = result["results"]
    if not results:
        console.print("[yellow]No matching nodes.[/yellow]")
        return
    table = Table(title=f"{result['backend']} query {result['query']!r}")
    for column in ("kind", "label", "degree"):
        table.add_column(column)
    for entry in results:
        table.add_row(str(entry["kind"]), str(entry["label"]), str(entry["degree"]))
    console.print(table)


# ── xrefs ──────────────────────────────────────────────────────────


@app.command()
def xrefs(
    function_id: int = typer.Argument(..., help="Function id whose references to list"),
    kind: list[str] | None = typer.Option(
        None, "--kind", help="Only show this ref kind (repeatable)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List cross-references to one function through the rebrew engine."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    kinds = [name for name in (kind or []) if name.strip()]
    with contextlib.closing(store.connect(portal_db)) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            _fail(f"no function with id {function_id}", json_output)
        binary_id = int(function["binary_id"])
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        va = int(function["va"])
        try:
            result = engine.xrefs(project_dir, va, kinds)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(result))
        return
    refs = result.get("refs")
    refs = refs if isinstance(refs, list) else []
    console.print(f"\n[bold cyan]function {function_id} @ 0x{va:x}[/bold cyan]")
    if not refs:
        console.print("[yellow]No cross-references.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Kind", style="cyan")
    table.add_column("From VA", style="magenta")
    table.add_column("Instruction")
    for ref in refs:
        table.add_row(
            str(ref.get("kind", "")),
            hex(int(ref.get("from_va", 0))),
            str(ref.get("instruction", "")),
        )
    console.print(table)


# ── references ─────────────────────────────────────────────────────


@app.command("references")
def references(
    function_id: int = typer.Argument(..., help="Function id whose references to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List a function's globals, callers and callees through the engine."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(
            f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            _fail(f"no function with id {function_id}", json_output)
        binary_id = int(function["binary_id"])
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        try:
            dossier = engine.describe(project_dir, int(function["va"]))
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(dossier))
        return
    callers = dossier.get("callers")
    callers = callers if isinstance(callers, list) else []
    callees = dossier.get("callees")
    callees = callees if isinstance(callees, list) else []
    globals_rows = dossier.get("globals")
    globals_rows = globals_rows if isinstance(globals_rows, list) else []
    console.print(f"\n[bold cyan]function {function_id} @ 0x{int(function['va']):x}[/bold cyan]")
    for title, rows, columns in (
        ("Globals", globals_rows, ("VA", "Kind")),
        ("Callers", callers, ("From VA", "Name")),
        ("Callees", callees, ("Target", "Name", "Kind")),
    ):
        console.print(f"[bold]{title}[/bold] ({len(rows)})")
        if not rows:
            console.print("  [dim]none[/dim]")
            continue
        table = Table(show_header=True, header_style="bold")
        for column in columns:
            table.add_column(column)
        for row in rows:
            if title == "Globals":
                table.add_row(hex(int(row.get("va", 0))), str(row.get("kind", "")))
            elif title == "Callers":
                table.add_row(hex(int(row.get("from_va", 0))), str(row.get("name") or ""))
            else:
                table.add_row(
                    hex(int(row.get("to_va", 0))),
                    str(row.get("name") or "indirect"),
                    str(row.get("kind", "")),
                )
        console.print(table)


# ── strings ────────────────────────────────────────────────────────


@app.command("strings")
def strings(
    binary_id: int = typer.Argument(..., help="Binary id whose strings to list"),
    sort: str = typer.Option("value", "--sort", help="Order by value or length"),
    order: str = typer.Option("asc", "--order", help="Direction: asc or desc"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List a binary's strings, sorted by value or length."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if sort not in store.STRING_SORTS:
        _fail(f"--sort must be one of {', '.join(store.STRING_SORTS)}", json_output)
    if order not in store.FUNCTION_ORDERS:
        _fail(f"--order must be one of {', '.join(store.FUNCTION_ORDERS)}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(
            f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            payload = engine.strings(path)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    entries = store.sort_string_entries(
        store.normalize_string_entries(payload), sort=sort, order=order
    )
    if json_output:
        typer.echo(json.dumps({"binary_id": binary_id, "count": len(entries), "strings": entries}))
        return
    for entry in entries[:_STRING_ROWS_SHOWN]:
        location = hex(entry["va"]) if entry["va"] is not None else "n/a"
        console.print(f"[magenta]{location}[/magenta] {entry['text']}")
    if len(entries) > _STRING_ROWS_SHOWN:
        console.print(f"[dim]... and {len(entries) - _STRING_ROWS_SHOWN} more[/dim]")


# ── structs ────────────────────────────────────────────────────────


@app.command()
def structs(
    binary_id: int = typer.Argument(..., help="Binary id whose structs to recover"),
    decompiler: str = typer.Option(
        engines.DEFAULT_DECOMPILER_BACKEND,
        "--decompiler",
        help="Decompiler backend: auto, kuna, r2ghidra, r2dec or ghidra",
    ),
    limit: int = typer.Option(0, "--limit", min=0, help="Maximum functions decompiled (0 = all)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Recover struct definitions through the rebrew engine and store the result."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if decompiler not in engines.DECOMPILER_BACKENDS:
        _fail(f"unknown decompiler backend: {decompiler}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        try:
            result = engine.structs(project_dir, decompiler=decompiler, limit=limit)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_STRUCTS, result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    recovered = result.get("structs")
    recovered = recovered if isinstance(recovered, list) else []
    console.print(
        f"\n[bold cyan]binary {binary_id}[/bold cyan]"
        f" decompiled {result.get('decompiled', 0)}, skipped {result.get('skipped', 0)}"
    )
    if not recovered:
        console.print("[yellow]No structs recovered.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("VA", style="magenta")
    table.add_column("Definition")
    for entry in recovered:
        table.add_row(
            str(entry.get("name", "")),
            hex(int(entry.get("va", 0))),
            str(entry.get("definition", "")),
        )
    console.print(table)


# ── data types ─────────────────────────────────────────────────────


@app.command()
def types(
    binary_id: int = typer.Argument(..., help="Binary id whose type model to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the binary's editable type model with sizes and offsets."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        model = data_types.list_types(conn, binary_id=binary_id)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "binary_id": binary_id,
                    "count": len(model),
                    "types": [data_types.encode_type(row) for row in model],
                }
            )
        )
        return
    if not model:
        console.print(
            "[yellow]No data types yet. Run 'reportal types-import"
            f" {binary_id}' after a structs run.[/yellow]"
        )
        return
    for data_type in model:
        namespace = str(data_type.get("namespace") or "")
        location = f" namespace {namespace}" if namespace else ""
        console.print(
            f"\n[bold cyan]{data_type['name']}[/bold cyan]{location}"
            f" kind {data_type['kind']} size {data_type['size']} ({data_type['source']})"
        )
        check = data_types.size_check(data_type)
        if check["warning"]:
            console.print(f"[yellow]{escape(str(check['warning']))}[/yellow]")
        if data_type["kind"] == data_types.KIND_ENUM:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Value", style="magenta", justify="right")
            table.add_column("Hex", justify="right")
            table.add_column("Name", style="cyan")
            for value in data_type["values"]:
                table.add_row(str(value["value"]), hex(int(value["value"])), str(value["name"]))
            console.print(table)
            continue
        if data_type["kind"] in (
            data_types.KIND_TYPEDEF,
            data_types.KIND_POINTER,
            data_types.KIND_ARRAY,
            data_types.KIND_FUNCTION,
        ):
            count = data_type.get("element_count")
            target = f"{data_type['target']}[{count}]" if count is not None else data_type["target"]
            console.print(f"target: {target}")
        if not data_type["members"]:
            continue
        table = Table(show_header=True, header_style="bold")
        table.add_column("Offset", style="magenta", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Member", style="cyan")
        table.add_column("Type")
        for member in data_type["members"]:
            table.add_row(
                hex(int(member["offset"])),
                str(member["size"]),
                str(member["name"]),
                _member_type_text(member),
            )
        console.print(table)


def _member_type_text(member: dict[str, Any]) -> str:
    """Render one model member's type the way the header does."""
    text = f"{member['type']} {'*' if member.get('pointer') else ''}".rstrip()
    count = member.get("count")
    return text if count is None else f"{text}[{count}]"


@app.command("types-import")
def types_import(
    binary_id: int = typer.Argument(..., help="Binary id whose structs scan to import"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Seed the type model from the binary's stored structs scan."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="data_types",
                where="binary_id = ?",
                params=(binary_id,),
                description=f"replaced the data types of binary {binary_id}",
            )
            try:
                summary = data_types.import_types(conn, binary_id=binary_id)
            except data_types.DataTypeError as exc:
                _fail(str(exc), json_output)
            journal.journaled_new_rows(
                conn,
                log,
                table="data_types",
                where="binary_id = ?",
                params=(binary_id,),
                before=before,
                key=("id",),
                description=f"imported a data type for binary {binary_id}",
            )

    if json_output:
        typer.echo(json.dumps(log.attach(summary)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Imported[/green] binary {binary_id}:"
        f" created {summary['created']}, updated {summary['updated']},"
        f" skipped {summary['skipped']}"
    )
    for entry in summary["skipped_types"]:
        console.print(f"[yellow]skipped[/yellow] {entry['name']}: {entry['reason']}")


@app.command("type-rename")
def type_rename(
    data_type_id: int = typer.Argument(..., help="Data type id to rename"),
    new_name: str = typer.Argument(..., help="New C identifier for the type"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rename one data type."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="data_types",
                where="id = ?",
                params=(data_type_id,),
                description=f"renamed data type {data_type_id}",
            )
            try:
                row = data_types.rename_type(conn, data_type_id, name=new_name)
            except data_types.DataTypeError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Renamed[/green] data type {data_type_id} to {row['name']}")


@app.command("type-member")
def type_member(
    data_type_id: int = typer.Argument(..., help="Data type id to edit"),
    member: str = typer.Argument(..., help="Member name, or its decimal index"),
    new_name: str = typer.Option("", "--new-name", help="New member name"),
    new_type: str = typer.Option("", "--new-type", help="New member type, e.g. 'unsigned int'"),
    new_bits: int = typer.Option(
        -1, "--new-bits", help="Bit width that makes the member a bitfield"
    ),
    clear_bits: bool = typer.Option(False, "--clear-bits", help="Drop the member's bit width"),
    new_count: int = typer.Option(-1, "--new-count", help="New array count"),
    clear_count: bool = typer.Option(False, "--clear-count", help="Drop the member's array count"),
    pointer: bool = typer.Option(False, "--pointer", help="Make the member a pointer"),
    no_pointer: bool = typer.Option(False, "--no-pointer", help="Make the member a non-pointer"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rename, retype or reshape one member of a data type.

    A retype replaces the member's type and leaves a hand-set bit width alone;
    ``--clear-bits`` (or ``--clear-count``) is what drops one.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if clear_bits and new_bits >= 0:
        _fail("--new-bits and --clear-bits are exclusive", json_output)
    if clear_count and new_count >= 0:
        _fail("--new-count and --clear-count are exclusive", json_output)
    edit: dict[str, Any] = {}
    if new_name:
        edit["new_name"] = new_name
    if new_type:
        edit["new_type"] = new_type
    if new_bits >= 0:
        edit["new_bits"] = new_bits
    if clear_bits:
        edit["new_bits"] = None
    if new_count >= 0:
        edit["new_count"] = new_count
    if clear_count:
        edit["new_count"] = None
    if pointer:
        edit["new_pointer"] = True
    if no_pointer:
        edit["new_pointer"] = False
    if not edit:
        _fail(
            "one of --new-name, --new-type, --new-bits, --clear-bits, --new-count,"
            " --clear-count, --pointer or --no-pointer is required",
            json_output,
        )
    selector: dict[str, Any] = {"index": int(member)} if member.isdigit() else {"name": member}
    log, row = _run_data_type_write(
        data_type_id,
        f"edited data type {data_type_id}",
        lambda conn: data_types.update_member(conn, data_type_id, **selector, **edit),
        json_output,
    )

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Updated[/green] data type {data_type_id}: {len(row['members'])} members")


def _run_data_type_write(
    data_type_id: int,
    description: str,
    run: Callable[[sqlite3.Connection], dict[str, Any]],
    json_output: bool,
) -> tuple[journal.Journal, dict[str, Any]]:
    """Run one journaled data-type write, exiting on a domain refusal.

    The row the write replaces and the history rows it appends are journaled
    together, the way the API and the MCP tools cover the same writes.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn, log, data_type_id, description, lambda: run(conn)
                )
            except data_types.DataTypeError as exc:
                _fail(str(exc), json_output)
    return log, row


@app.command("type-kind")
def type_kind(
    data_type_id: int = typer.Argument(..., help="Data type id to switch"),
    kind: str = typer.Argument(..., help="New declaration kind, e.g. 'union'"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Switch a type's declaration kind and recompute its size from the new shape."""
    log, row = _run_data_type_write(
        data_type_id,
        f"changed the kind of data type {data_type_id}",
        lambda conn: data_types.set_kind(conn, data_type_id, kind=kind),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Set[/green] data type {data_type_id} kind to {row['kind']} (size {row['size']})"
    )


@app.command("type-namespace")
def type_namespace(
    data_type_id: int = typer.Argument(..., help="Data type id to move"),
    namespace: str = typer.Argument(..., help="Namespace path; an empty string clears it"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Set a type's namespace; an empty string makes it program-defined."""
    log, row = _run_data_type_write(
        data_type_id,
        f"set the namespace of data type {data_type_id}",
        lambda conn: data_types.set_namespace(conn, data_type_id, namespace=namespace),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    location = str(row["namespace"]) or "(program)"
    console.print(f"[green]Set[/green] data type {data_type_id} namespace to {location}")


@app.command("type-size")
def type_size(
    data_type_id: int = typer.Argument(..., help="Data type id whose size to declare"),
    size: int = typer.Argument(..., help="Declared size in bytes"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Declare a type's size without touching its members.

    The check in the response names both numbers when the declared size and the
    members' extent disagree; neither is rewritten.
    """
    log, row = _run_data_type_write(
        data_type_id,
        f"declared the size of data type {data_type_id}",
        lambda conn: data_types.set_size(conn, data_type_id, size=size),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    check = row["size_check"]
    console.print(f"[green]Declared[/green] data type {data_type_id} size {check['declared']}")
    if check["warning"]:
        console.print(f"[yellow]{escape(check['warning'])}[/yellow]")


@app.command("type-member-add")
def type_member_add(
    data_type_id: int = typer.Argument(..., help="Data type id to add to"),
    name: str = typer.Argument(..., help="New member name"),
    type_text: str = typer.Argument(..., help="New member type, e.g. 'unsigned int'"),
    pointer: bool = typer.Option(False, "--pointer", help="Make the member a pointer"),
    count: int = typer.Option(-1, "--count", help="Array count"),
    bits: int = typer.Option(-1, "--bits", help="Bit width that makes the member a bitfield"),
    index: int = typer.Option(-1, "--index", help="Position the member takes"),
    after: str = typer.Option("", "--after", help="Insert the member after this member"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add one member, appended or at a position.

    ``--index`` is the position the member takes and ``--after`` names the member
    it follows; naming both is refused rather than silently picking one, and
    naming neither appends.
    """
    if index >= 0 and after:
        _fail("--index and --after are exclusive", json_output)
    log, row = _run_data_type_write(
        data_type_id,
        f"added a member to data type {data_type_id}",
        lambda conn: data_types.add_member(
            conn,
            data_type_id,
            name=name,
            type_text=type_text,
            pointer=True if pointer else None,
            count=None if count < 0 else count,
            bits=None if bits < 0 else bits,
            index=None if index < 0 else index,
            after=after or None,
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Added[/green] {name} to data type {data_type_id}:"
        f" {len(row['members'])} members, size {row['size']}"
    )


@app.command("type-member-gap")
def type_member_gap(
    data_type_id: int = typer.Argument(..., help="Data type id to edit"),
    member: str = typer.Argument(..., help="Member name, or its decimal index"),
    size: int = typer.Option(-1, "--size", help="Bytes the gap covers (default: the member's)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Convert one member to explicit padding named after its offset."""
    selector: dict[str, Any] = {"index": int(member)} if member.isdigit() else {"name": member}
    log, row = _run_data_type_write(
        data_type_id,
        f"converted a member of data type {data_type_id} to a gap",
        lambda conn: data_types.convert_to_gap(
            conn, data_type_id, **selector, size=None if size < 0 else size
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Converted[/green] {member} of data type {data_type_id} to a gap")


@app.command("type-member-ungap")
def type_member_ungap(
    data_type_id: int = typer.Argument(..., help="Data type id to edit"),
    member: str = typer.Argument(..., help="Gap name, or its decimal index"),
    name: str = typer.Argument(..., help="Name the member takes"),
    type_text: str = typer.Argument(..., help="Type the member takes"),
    pointer: bool = typer.Option(False, "--pointer", help="Make the member a pointer"),
    count: int = typer.Option(-1, "--count", help="Array count"),
    bits: int = typer.Option(-1, "--bits", help="Bit width that makes the member a bitfield"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Turn one padding member back into a named, typed member."""
    selector: dict[str, Any] = {"index": int(member)} if member.isdigit() else {"name": member}
    log, row = _run_data_type_write(
        data_type_id,
        f"converted a gap of data type {data_type_id} to a member",
        lambda conn: data_types.convert_from_gap(
            conn,
            data_type_id,
            **selector,
            new_name=name,
            new_type=type_text,
            pointer=True if pointer else data_types.UNSET,
            count=data_types.UNSET if count < 0 else count,
            bits=data_types.UNSET if bits < 0 else bits,
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Converted[/green] {member} of data type {data_type_id} to a member")


@app.command("type-value-add")
def type_value_add(
    data_type_id: int = typer.Argument(..., help="Enum type id to add to"),
    name: str = typer.Argument(..., help="New constant name"),
    value: str = typer.Option("", "--value", help="Value as decimal or 0x hex; default: increment"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Append one enum constant, auto-incrementing when no value is given."""
    log, row = _run_data_type_write(
        data_type_id,
        f"added an enum value to data type {data_type_id}",
        lambda conn: data_types.add_value(conn, data_type_id, name=name, value=value or None),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    entry = row["values"][-1]
    note = row.get("note")
    console.print(
        f"[green]Added[/green] {entry['name']} = {entry['value']} ({entry['hex']})"
        + (f" [dim]{escape(str(note))}[/dim]" if note else "")
    )


@app.command("type-value-edit")
def type_value_edit(
    data_type_id: int = typer.Argument(..., help="Enum type id to edit"),
    value: str = typer.Argument(..., help="Constant name, or its decimal index"),
    new_name: str = typer.Option("", "--new-name", help="New constant name"),
    new_value: str = typer.Option("", "--new-value", help="New value, decimal or 0x hex"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Rename and/or revalue one enum constant."""
    if not new_name and not new_value:
        _fail("one of --new-name or --new-value is required", json_output)
    selector: dict[str, Any] = {"index": int(value)} if value.isdigit() else {"name": value}
    log, row = _run_data_type_write(
        data_type_id,
        f"edited an enum value of data type {data_type_id}",
        lambda conn: data_types.update_value(
            conn,
            data_type_id,
            **selector,
            new_name=new_name or None,
            new_value=new_value or None,
        ),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Edited[/green] data type {data_type_id}: {len(row['values'])} enum values"
    )


@app.command("type-value-remove")
def type_value_remove(
    data_type_id: int = typer.Argument(..., help="Enum type id to edit"),
    value: str = typer.Argument(..., help="Constant name, or its decimal index"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove one enum constant."""
    selector: dict[str, Any] = {"index": int(value)} if value.isdigit() else {"name": value}
    log, row = _run_data_type_write(
        data_type_id,
        f"removed an enum value from data type {data_type_id}",
        lambda conn: data_types.remove_value(conn, data_type_id, **selector),
        json_output,
    )
    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Removed[/green] {value} from data type {data_type_id}")


@app.command("types-export")
def types_export(
    binary_id: int = typer.Argument(..., help="Binary id whose model to export"),
    path: Path = typer.Argument(..., help="Header path to write"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Render the type model as one C header at an explicit path."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        target = path.expanduser()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            try:
                summary = data_types.export_header(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except data_types.DataTypeError as exc:
                _fail(str(exc), json_output)
            journal.journaled_file(log, target, previous=previous)

    if json_output:
        typer.echo(json.dumps(log.attach(summary)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Wrote[/green] {summary['bytes']} bytes"
        f" ({summary['types']} types) to {summary['path']}"
    )


def _print_history_entry(entry: dict[str, Any]) -> None:
    """One line for a history entry's header, then one line per field change."""
    console.print(
        f"[bold]#{entry['id']}[/bold] [dim]{entry['source'] or 'manual'}"
        f" ({entry['actor'] or 'manual'}) {entry['created_at']}[/dim]"
    )
    if entry["previous"] is None:
        console.print("  created")
    elif entry["current"] is None:
        console.print("  deleted")
    for change in entry["changes"]:
        console.print(
            f"  {change['field']}: {_history_value(change['before'])}"
            f" -> {_history_value(change['after'])}"
        )


def _history_value(value: Any) -> str:
    """Render one recorded field value the way a history listing shows it."""
    if isinstance(value, list):
        return str(len(value))
    if value is None or value == "":
        return "n/a"
    return str(value)


@app.command("types-history")
def types_history(
    data_type_id: int = typer.Argument(..., help="Data type id whose history to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List a type's edit history, newest first, with each entry's field diff.

    The history rows outlive the type: a deleted type is still listed here and
    its revert restores the row.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        history = data_types.list_history(conn, data_type_id)
        row = store.get_data_type(conn, data_type_id)

    payload = {
        "data_type_id": data_type_id,
        "exists": row is not None,
        "count": len(history),
        "history": history,
    }
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if not history:
        console.print(f"[yellow]No history for data type {data_type_id}.[/yellow]")
        return
    for entry in history:
        _print_history_entry(entry)


@app.command("types-revert")
def types_revert(
    data_type_id: int = typer.Argument(..., help="Data type id whose state to restore"),
    history_id: int = typer.Argument(..., help="Data-type history id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Restore the state one data-type history row recorded."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"reverted data type {data_type_id}",
                    lambda: data_types.revert_history(conn, data_type_id, history_id),
                )
            except data_types.DataTypeError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    if not result["changed"]:
        console.print(f"[yellow]Nothing to revert: {result['reason']}[/yellow]")
        return
    restored = result["data_type"]
    if restored is None:
        console.print(f"[green]Removed[/green] data type {data_type_id}")
        return
    console.print(f"[green]Restored[/green] data type {data_type_id}: {restored['name']}")


# ── signatures ─────────────────────────────────────────────────────


@app.command("signatures")
def signatures_list(
    binary_id: int = typer.Argument(..., help="Binary id whose signatures to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List the binary's stored function signatures."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        model = signatures.list_signatures(conn, binary_id=binary_id)

    if json_output:
        typer.echo(json.dumps({"binary_id": binary_id, "count": len(model), "signatures": model}))
        return
    if not model:
        console.print(
            "[yellow]No signatures yet. Run 'reportal signatures-import"
            f" {binary_id}' after decompiling.[/yellow]"
        )
        return
    for row in model:
        console.print(
            f"\n[bold cyan]{signatures.render_prototype(row)}[/bold cyan]"
            f" ({row['source'] or 'manual'})"
        )


@app.command("signatures-import")
def signatures_import(
    binary_id: int = typer.Argument(..., help="Binary id whose decompilations to parse"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Seed the signature model from the binary's stored decompilations."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="function_signatures",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
                description=f"replaced the signatures of binary {binary_id}",
            )
            history_before = journal.snapshot_rows(
                conn,
                table="signature_history",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
            )
            summary = signatures.seed_signatures(conn, binary_id=binary_id)
            journal.journaled_new_rows(
                conn,
                log,
                table="function_signatures",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
                before=before,
                key=("function_id",),
                description=f"imported a signature for binary {binary_id}",
            )
            journal.journaled_new_rows(
                conn,
                log,
                table="signature_history",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
                before=history_before,
                key=("id",),
                description=f"signature history of binary {binary_id}",
            )

    if json_output:
        typer.echo(json.dumps(log.attach(summary)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Imported[/green] binary {binary_id}:"
        f" created {summary['created']}, updated {summary['updated']},"
        f" skipped {summary['skipped']}"
    )
    for entry in summary["skipped_functions"]:
        console.print(f"[yellow]skipped[/yellow] {entry['name']}: {entry['reason']}")


@app.command("signature")
def signature(
    function_id: int = typer.Argument(..., help="Function id whose signature to show"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show one function's stored signature and its rendered prototype."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        row = signatures.get_signature(conn, function_id)
    if row is None:
        _fail(f"function {function_id} has no signature", json_output)

    if json_output:
        typer.echo(json.dumps(row))
        return
    console.print(f"[bold cyan]{signatures.render_prototype(row)}[/bold cyan]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Index", style="magenta", justify="right")
    table.add_column("Type", style="cyan")
    table.add_column("Name")
    for parameter in row["parameters"]:
        table.add_row(str(parameter["index"]), str(parameter["type"]), str(parameter["name"] or ""))
    console.print(table)


@app.command("signature-set")
def signature_set(
    function_id: int = typer.Argument(..., help="Function id whose signature to edit"),
    return_type: str = typer.Option("", "--return-type", help="New return type"),
    convention: str = typer.Option("", "--convention", help="New calling convention, e.g. stdcall"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Set one signature's return type and/or calling convention."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if not return_type and not convention:
        _fail("one of --return-type or --convention is required", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:

            def edit() -> dict[str, Any]:
                row = signatures.get_signature(conn, function_id)
                if row is None:
                    raise signatures.UnknownSignatureError(
                        f"function {function_id} has no signature"
                    )
                if return_type:
                    row = signatures.set_return_type(conn, function_id, return_type=return_type)
                if convention:
                    row = signatures.set_calling_convention(
                        conn, function_id, calling_convention=convention
                    )
                return row

            try:
                row = _journal_signature_write(
                    conn, log, function_id, f"edited signature of {function_id}", edit
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Updated[/green] signature {function_id}: {signatures.render_prototype(row)}"
    )


@app.command("signature-param")
def signature_param(
    function_id: int = typer.Argument(..., help="Function id whose signature to edit"),
    index: int = typer.Argument(..., help="Parameter index to edit"),
    type_text: str = typer.Option("", "--type", help="New parameter type"),
    name: str = typer.Option("", "--name", help="New parameter name"),
    at: str | None = typer.Option(
        None, "--at", help="Argument location: a register (ecx) or a stack slot ([esp+4])"
    ),
    kind: str | None = typer.Option(
        None, "--kind", help="Parameter kind: value, pointer, array or struct"
    ),
    bits: int | None = typer.Option(None, "--bits", help="Parameter width in bits"),
    clear: list[str] | None = typer.Option(
        None, "--clear", help="Clear a field (repeatable): at, kind or bits"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Edit one parameter's type, name, arrival location, kind or width."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    clears = {value.strip().lower() for value in (clear or []) if value.strip()}
    unknown = clears - {"at", "kind", "bits"}
    if unknown:
        _fail(f"--clear names an unknown field: {', '.join(sorted(unknown))}", json_output)
    edits: dict[str, Any] = {}
    if type_text:
        edits["type_text"] = type_text
    if name:
        edits["name"] = name
    for key, value in (("at", at), ("kind", kind), ("bits", bits)):
        if key in clears:
            edits[key] = None
        elif value is not None:
            edits[key] = value
    if not edits:
        _fail("one of --type, --name, --at, --kind, --bits or --clear is required", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"edited a parameter of signature {function_id}",
                    lambda: signatures.set_parameter(conn, function_id, index=index, **edits),
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Updated[/green] parameter {index}: {signatures.render_prototype(row)}")


@app.command("signature-param-move")
def signature_param_move(
    function_id: int = typer.Argument(..., help="Function id whose signature to edit"),
    index: int = typer.Argument(..., help="Parameter index to move"),
    to_index: int = typer.Argument(..., help="Position to move it to"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Move one parameter, recomputing the arrival locations the convention implies."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"reordered a parameter of signature {function_id}",
                    lambda: signatures.move_parameter(
                        conn, function_id, index=index, to_index=to_index
                    ),
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Moved[/green] parameter {index} to {to_index}")


@app.command("signature-param-add")
def signature_param_add(
    function_id: int = typer.Argument(..., help="Function id whose signature to edit"),
    type_text: str = typer.Option(..., "--type", help="Parameter type"),
    name: str = typer.Option("", "--name", help="Parameter name"),
    index: int | None = typer.Option(None, "--index", help="Insert position (default appends)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Add one parameter to a signature, appended or at the named index."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"added a parameter to signature {function_id}",
                    lambda: signatures.add_parameter(
                        conn, function_id, type_text=type_text, name=name, index=index
                    ),
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Added[/green] parameter: {signatures.render_prototype(row)}")


@app.command("signature-param-rm")
def signature_param_rm(
    function_id: int = typer.Argument(..., help="Function id whose signature to edit"),
    index: int = typer.Argument(..., help="Parameter index to remove"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Remove one parameter from a signature, reindexing the rest."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"removed a parameter of signature {function_id}",
                    lambda: signatures.remove_parameter(conn, function_id, index=index),
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(row)))
        return
    _print_journal_action(log, json_output)
    console.print(f"[green]Removed[/green] parameter {index}: {signatures.render_prototype(row)}")


@app.command("signatures-export")
def signatures_export(
    binary_id: int = typer.Argument(..., help="Binary id whose signatures to export"),
    path: Path = typer.Argument(..., help="Header path to write"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Render the signature model as one C prototype header at an explicit path."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        target = path.expanduser()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            try:
                summary = signatures.export_prototypes(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except signatures.SignatureError as exc:
                _fail(str(exc), json_output)
            journal.journaled_file(log, target, previous=previous)

    if json_output:
        typer.echo(json.dumps(log.attach(summary)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Wrote[/green] {summary['bytes']} bytes"
        f" ({summary['signatures']} signatures) to {summary['path']}"
    )


@app.command("signature-history")
def signature_history(
    function_id: int = typer.Argument(..., help="Function id whose signature history to list"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List a function's signature-edit history, newest first."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        history = signatures.list_history(conn, function_id)

    if json_output:
        typer.echo(
            json.dumps({"function_id": function_id, "count": len(history), "history": history})
        )
        return
    if not history:
        console.print("[yellow]No signature history yet.[/yellow]")
        return
    for entry in history:
        previous = entry["previous"]
        rendered = signatures.render_prototype(previous) if previous else "no signature"
        console.print(
            f"[bold]#{entry['id']}[/bold] [dim]{entry['source'] or 'manual'}"
            f" ({entry['actor'] or 'manual'}) {entry['created_at']}[/dim] {rendered}"
        )


@app.command("signature-revert")
def signature_revert(
    function_id: int = typer.Argument(..., help="Function id whose signature to restore"),
    history_id: int = typer.Argument(..., help="Signature-history id to revert"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Restore the signature state one history row recorded."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_function(conn, function_id) is None:
            _fail(f"no function with id {function_id}", json_output)
        entry = signatures.get_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            _fail(f"no history {history_id} for function {function_id}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = _journal_signature_write(
                conn,
                log,
                function_id,
                f"reverted signature of {function_id}",
                lambda: signatures.revert_history(conn, function_id, history_id),
            )

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    restored = result["signature"]
    if restored is None:
        console.print(f"[green]Removed[/green] signature {function_id}")
        return
    console.print(
        f"[green]Restored[/green] signature {function_id}: {signatures.render_prototype(restored)}"
    )


# ── memory ─────────────────────────────────────────────────────────


@app.command("memory")
def memory(
    binary_id: int = typer.Argument(..., help="Binary id whose bytes to read"),
    address: str = typer.Argument(..., help="Address to read from (hex or decimal)"),
    length: int = typer.Option(
        engines.MEMORY_READ_DEFAULT,
        "--length",
        help=(
            f"Bytes to read (default {engines.MEMORY_READ_DEFAULT}, max {engines.MEMORY_READ_MAX})"
        ),
    ),
    offset_kind: str = typer.Option(
        engines.MEMORY_ADDRESS_KIND_VA,
        "--offset-kind",
        help="Address kind: va (absolute), rva (relative to the image base) or file",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Read a window of a binary's bytes by address through the engine."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if length <= 0 or length > engines.MEMORY_READ_MAX:
        _fail(f"--length must be between 1 and {engines.MEMORY_READ_MAX}", json_output)
    if offset_kind not in engines.MEMORY_ADDRESS_KINDS:
        kinds = ", ".join(sorted(engines.MEMORY_ADDRESS_KINDS))
        _fail(f"--offset-kind must be one of {kinds}", json_output)
    try:
        parsed_address = int(address, 0)
    except ValueError:
        _fail(f"address must be an integer or 0x-prefixed hex: {address}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(
            f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            window = engine.read_memory(
                path, address=parsed_address, length=length, kind=offset_kind
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    payload = {"binary_id": binary_id, **window}
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[cyan]{payload['kind']}[/cyan] {payload['address']}"
        f" ({payload['length']} bytes{', ' + payload['section'] if payload['section'] else ''})"
    )
    console.print(payload["bytes"])


# ── section-coverage ───────────────────────────────────────────────


@app.command("memory-page")
def memory_page(
    binary_id: int = typer.Argument(..., help="Binary id whose bytes to page"),
    address: str | None = typer.Argument(
        None, help="Page start (hex or decimal); default: the first section"
    ),
    length: int = typer.Option(
        engines.MEMORY_PAGE_DEFAULT,
        "--length",
        help=f"Page size (default {engines.MEMORY_PAGE_DEFAULT}, max {engines.MEMORY_PAGE_MAX})",
    ),
    offset_kind: str = typer.Option(
        engines.MEMORY_ADDRESS_KIND_VA,
        "--offset-kind",
        help="Address kind: va (absolute), rva (relative to the image base) or file",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Page the binary's bytes for the full-file view, gaps stated as gaps."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if length <= 0 or length > engines.MEMORY_PAGE_MAX:
        _fail(f"--length must be between 1 and {engines.MEMORY_PAGE_MAX}", json_output)
    if offset_kind not in engines.MEMORY_ADDRESS_KINDS:
        kinds = ", ".join(sorted(engines.MEMORY_ADDRESS_KINDS))
        _fail(f"--offset-kind must be one of {kinds}", json_output)
    parsed_address: int | None = None
    if address is not None:
        try:
            parsed_address = int(address, 0)
        except ValueError:
            _fail(f"address must be an integer or 0x-prefixed hex: {address}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(
            f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}",
            json_output,
        )
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            page = engine.read_memory_page(
                path, address=parsed_address, length=length, kind=offset_kind
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    payload = {"binary_id": binary_id, **page}
    if json_output:
        typer.echo(json.dumps(payload))
        return
    console.print(
        f"[cyan]{payload['kind']}[/cyan] {payload['start']} ({payload['length']} bytes,"
        f" {payload['mapped']} mapped, {payload['gaps']} in gaps)"
    )
    for row in payload["rows"]:
        if row["kind"] == "gap":
            console.print(f"[dim]{row['address']} gap ({row['length']} bytes)[/dim]")
        else:
            console.print(f"{row['address']} {row['offset']} {row['hex']}")


@app.command("section-coverage")
def section_coverage(
    binary_id: int = typer.Argument(..., help="Binary id whose byte coverage to report"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Report per-section byte coverage over the stored functions (reportal's own metric)."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        coverage = store.section_byte_coverage(conn, binary_id)

    if coverage is None:
        _fail(
            f"no pe-info scan for binary {binary_id}; run 'reportal pe-info {binary_id}' first",
            json_output,
        )
    if json_output:
        typer.echo(json.dumps(coverage))
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Section", style="cyan")
    table.add_column("VA", style="magenta", justify="right")
    table.add_column("Covered", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Coverage", justify="right")
    for section in coverage["sections"]:
        percent = section["coverage_pct"]
        table.add_row(
            section["name"],
            hex(section["va"]),
            str(section["covered"]),
            str(section["size"]),
            "n/a" if percent is None else f"{percent}%",
        )
    console.print(table)
    totals = coverage["totals"]
    percent = totals["coverage_pct"]
    console.print(
        f"{totals['covered']} / {totals['size']} bytes"
        f" ({'n/a' if percent is None else f'{percent}%'}),"
        f" {totals['uncovered']} uncovered"
    )
    console.print(f"[dim]{coverage['note']}[/dim]")


# ── crypto-scan ────────────────────────────────────────────────────


@app.command("crypto-scan")
def crypto_scan(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan a binary for crypto constants and APIs through the rebrew engine."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            result = engine.crypto_scan(path)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_CRYPTO, result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    if not findings:
        console.print("[yellow]No crypto indicators.[/yellow]")
        return
    by_confidence = result.get("by_confidence")
    by_confidence = by_confidence if isinstance(by_confidence, dict) else {}
    console.print(
        f"{result.get('count', len(findings))} findings,"
        f" high {by_confidence.get('high', 0)}, medium {by_confidence.get('medium', 0)}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Confidence", style="cyan")
    table.add_column("Kind")
    table.add_column("Name")
    table.add_column("Detail")
    for finding in findings:
        table.add_row(
            str(finding.get("confidence", "")),
            str(finding.get("kind", "")),
            str(finding.get("name", "")),
            str(finding.get("detail", "")),
        )
    console.print(table)


# ── pe-info ────────────────────────────────────────────────────────

# Section flags `_print_pe_info` renders, in display order; an absent flag
# renders as a dash.
_SECTION_ACCESS = (("read", "R"), ("write", "W"), ("execute", "X"))


@app.command()
def die_info(
    binary_id: int = typer.Argument(..., help="Binary id to identify"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Identify a binary the way Detect-It-Easy does, from the stored scans.

    Reads the stored `filetype` and `pe-info` scans and the stored fingerprint,
    so it runs no engine: run those first when a category comes back empty, and
    the payload's `sources` names each one.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        payload = details.die_info(conn, binary_id)
    if not payload["available"]:
        _fail(f"binary {binary_id} has no stored filetype or pe-info scan", json_output)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    identity = payload["identity"]
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("format", str(identity["format"]))
    table.add_row("architecture", str(identity["arch"]))
    table.add_row("bits", str(identity["bits"]))
    table.add_row("mode", str(identity["mode"]))
    for category in ("packer", "protector", "installer", "runtime", "toolchain"):
        found = payload[category]
        table.add_row(category, ", ".join(str(row["name"]) for row in found) or "none")
    if payload["packer_section_hint"]:
        table.add_row("section hint", ", ".join(payload["packer_section_hint"]))
    console.print(table)


@app.command()
def additional_details(
    binary_id: int = typer.Argument(..., help="Binary id to describe"),
    status: bool = typer.Option(False, "--status", help="Report which sources exist instead"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show a binary's overlay, Rich header, debug and directory presence.

    A read of the stored `pe-info` scan; `--status` reports which sources exist
    without needing one, so it never fails on a binary that has not been
    inspected yet.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        if status:
            payload = details.status(conn, binary_id)
        else:
            if not details.source_present(conn, binary_id, store.SCAN_KIND_PE_INFO):
                _fail(
                    f"binary {binary_id} has no stored pe-info scan"
                    f" (run 'reportal pe-info {binary_id}')",
                    json_output,
                )
            payload = details.additional_details(conn, binary_id)
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if status:
        console.print(f"status: {payload['status']}")
        if payload["hint"]:
            console.print(f"hint: {payload['hint']}")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("format", str(payload["format"]))
    table.add_row("size", str(payload["size"]))
    overlay = payload["overlay"]
    table.add_row("overlay", f"{overlay['bytes']} bytes" if overlay["present"] else "none")
    rich = payload["rich_header"]
    table.add_row("rich header", f"{rich['entries']} entries" if rich["present"] else "absent")
    table.add_row("debug entries", str(len(payload["debug"])))
    table.add_row("sections", ", ".join(payload["sections"]["names"]))
    present = [name for name, found in payload["presence"].items() if found]
    table.add_row("directories", ", ".join(present) or "none")
    console.print(table)


@app.command("pe-info")
def pe_info(
    binary_id: int = typer.Argument(..., help="Binary id to inspect"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Inspect a binary's PE identity, sections and security metadata."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            result = engine.pe_info(path)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_PE_INFO, result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _print_pe_info(binary_id, result)


def _print_pe_info(binary_id: int, result: dict[str, Any]) -> None:
    """Render a `rebrew pe-info` payload for the terminal."""
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    identity = [str(result.get("format", "")), str(result.get("arch", ""))]
    if isinstance(result.get("bits"), int):
        identity.append(f"{result['bits']}-bit")
    if any(identity):
        console.print(" ".join(part for part in identity if part))
    console.print(
        f"subsystem {result.get('subsystem') or 'n/a'},"
        f" image base {_as_hex(result.get('image_base'))},"
        f" entry point {_as_hex(result.get('entry_point'))}"
    )
    console.print(
        f"timestamp {result.get('timestamp_iso') or 'n/a'},"
        f" checksum {_pe_number(result.get('checksum'))}, size {_pe_number(result.get('size'))}"
    )
    note = result.get("note")
    if note:
        console.print(f"[yellow]{note}[/yellow]")
    security = result.get("security_flags")
    security = security if isinstance(security, dict) else {}
    flags = result.get("flags_summary")
    flags = [str(flag) for flag in flags] if isinstance(flags, list) else []
    console.print(
        f"security flags: {', '.join(flags) if flags else 'none'}"
        f" (dll_characteristics {_as_hex(security.get('dll_characteristics'))})"
    )
    sections = result.get("sections")
    sections = sections if isinstance(sections, list) else []
    if sections:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Section", style="cyan")
        table.add_column("VA")
        table.add_column("Virtual size")
        table.add_column("Raw size")
        table.add_column("Protections")
        for section in sections:
            table.add_row(
                str(section.get("name", "")),
                _as_hex(section.get("virtual_address")),
                str(section.get("virtual_size", "")),
                str(section.get("raw_size", "")),
                _section_protections(section),
            )
        console.print(table)
    debug = result.get("debug")
    debug = debug if isinstance(debug, list) else []
    debug_types = ", ".join(str(entry.get("type", "")) for entry in debug if entry.get("type"))
    console.print(f"debug info: {debug_types or 'none'}")
    rich_header = result.get("rich_header")
    rich_header = rich_header if isinstance(rich_header, dict) else {}
    entries = rich_header.get("entries")
    entries = entries if isinstance(entries, list) else []
    rich_text = f"present ({len(entries)} entries)" if rich_header.get("present") else "absent"
    console.print(f"rich header: {rich_text}")
    authenticode = result.get("authenticode")
    authenticode = authenticode if isinstance(authenticode, dict) else {}
    signed = "signed" if authenticode.get("present") else "not signed"
    console.print(f"authenticode: {signed} ({authenticode.get('signature_count', 0)} signatures)")


def _as_hex(value: Any) -> str:
    """Render *value* as a hex address, or ``n/a`` when it is not an integer."""
    return hex(int(value)) if isinstance(value, int) else "n/a"


def _pe_number(value: Any) -> str:
    """Render an identity number, or ``n/a`` when it is absent."""
    return str(value) if isinstance(value, int) else "n/a"


def _section_protections(section: dict[str, Any]) -> str:
    """Render a section's read/write/execute flags as three letters."""
    return "".join(letter if section.get(access) else "-" for access, letter in _SECTION_ACCESS)


# ── filetype ───────────────────────────────────────────────────────


@app.command("filetype")
def filetype(
    binary_id: int = typer.Argument(..., help="Binary id to inspect"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Detect a binary's file type, packer and protector signatures."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_FILETYPE,
                lambda: filetypes.run_filetype(conn, binary_id=binary_id, engine=engine),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _print_filetype(binary_id, result)


def _print_filetype(binary_id: int, result: dict[str, Any]) -> None:
    """Render a file-type detection for the terminal."""
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    matches = result.get("matches")
    matches = matches if isinstance(matches, list) else []
    notes = result.get("notes")
    notes = notes if isinstance(notes, list) else []
    if not matches:
        console.print("[yellow]No signatures matched.[/yellow]")
        for note in notes:
            console.print(f"[yellow]{note}[/yellow]")
        return
    by_category = result.get("by_category")
    by_category = by_category if isinstance(by_category, dict) else {}
    summary = ", ".join(f"{name} {by_category.get(name, 0)}" for name in filetypes.FILE_CATEGORIES)
    console.print(f"{result.get('count', len(matches))} matches ({summary})")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Confidence")
    table.add_column("Signals")
    for match in matches:
        signals = match.get("signals")
        signals = signals if isinstance(signals, list) else []
        rendered = ", ".join(f"{signal.get('kind')}: {signal.get('value')}" for signal in signals)
        table.add_row(
            str(match.get("name", "")),
            str(match.get("category", "")),
            str(match.get("confidence", "")),
            rendered,
        )
    console.print(table)
    for note in notes:
        console.print(f"[yellow]{note}[/yellow]")


# ── capabilities ───────────────────────────────────────────────────


@app.command("capabilities")
def capabilities_command(
    binary_id: int = typer.Argument(..., help="Binary id to classify"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Classify a binary's capabilities from its imports and strings."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_CAPABILITIES,
                lambda: capabilities.run_capabilities(conn, binary_id=binary_id, engine=engine),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    detected = result["capabilities"]
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    if not detected:
        console.print("[yellow]No capabilities detected.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Confidence")
    table.add_column("Evidence", justify="right")
    table.add_column("Description")
    for entry in detected:
        table.add_row(
            str(entry["name"]),
            str(entry["confidence"]),
            str(entry["evidence_count"]),
            str(entry["description"]),
        )
    console.print(table)
    console.print(f"{result['count']} capabilities")


# ── secrets ────────────────────────────────────────────────────────


@app.command("secrets")
def secrets_command(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan a binary's strings for hardcoded secrets and high-entropy values."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_SECRETS,
                lambda: secrets.run_secrets(conn, binary_id=binary_id, engine=engine),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    if not findings:
        console.print("[yellow]No secrets found.[/yellow]")
        return
    console.print(
        "[bold red]Warning:[/bold red] findings contain live secrets;"
        " the values are sensitive and are stored locally."
    )
    by_confidence = result.get("by_confidence")
    by_confidence = by_confidence if isinstance(by_confidence, dict) else {}
    console.print(
        f"{result.get('count', len(findings))} findings,"
        f" high {by_confidence.get('high', 0)}, medium {by_confidence.get('medium', 0)},"
        f" {result.get('scanned', 0)} strings scanned"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Confidence", style="cyan")
    table.add_column("Kind")
    table.add_column("Name")
    table.add_column("Redacted", style="magenta")
    table.add_column("VA", style="magenta")
    for finding in findings:
        va = finding.get("va")
        table.add_row(
            str(finding.get("confidence", "")),
            str(finding.get("kind", "")),
            str(finding.get("name", "")),
            str(finding.get("redacted", "")),
            hex(int(va)) if isinstance(va, int) else "",
        )
    console.print(table)


# ── protocols ──────────────────────────────────────────────────────


# Evidence values rendered per protocol row; the stored evidence list stays
# complete and the table shows a sample of it.
MAX_EVIDENCE_SHOWN = 4


def _print_protocols(binary_id: int, result: dict[str, Any]) -> None:
    """Print a protocol scan's confidence counts and its protocol table."""
    found = result.get("protocols")
    found = found if isinstance(found, list) else []
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    if not found:
        console.print("[yellow]No protocols inferred.[/yellow]")
        return
    by_confidence = result.get("by_confidence")
    by_confidence = by_confidence if isinstance(by_confidence, dict) else {}
    console.print(
        f"{result.get('count', len(found))} protocols,"
        f" high {by_confidence.get('high', 0)}, medium {by_confidence.get('medium', 0)}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Protocol", style="cyan")
    table.add_column("Confidence")
    table.add_column("Ports")
    table.add_column("Evidence")
    for entry in found:
        evidence = entry.get("evidence")
        evidence = evidence if isinstance(evidence, list) else []
        shown = [
            f"{item.get('kind')}: {item.get('value')}"
            for item in evidence[:MAX_EVIDENCE_SHOWN]
            if isinstance(item, dict)
        ]
        if len(evidence) > MAX_EVIDENCE_SHOWN:
            shown.append(f"+{len(evidence) - MAX_EVIDENCE_SHOWN} more")
        ports = entry.get("ports")
        ports = ports if isinstance(ports, list) else []
        table.add_row(
            str(entry.get("protocol", "")),
            str(entry.get("confidence", "")),
            ", ".join(str(port) for port in ports) or "-",
            "; ".join(shown) or "-",
        )
    console.print(table)


@app.command("protocols")
def protocols_command(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Infer the network protocols a binary speaks from its imports and strings."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_PROTOCOLS,
                lambda: protocols.scan_protocols(conn, binary_id=binary_id, engine=engine),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _print_protocols(binary_id, result)


# ── behavior ───────────────────────────────────────────────────────


def _print_behavior(binary_id: int, domain: str, result: dict[str, Any]) -> None:
    """Print one behavior scan's confidence counts and findings table."""
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    console.print(f"\n[bold cyan]binary {binary_id} {domain}[/bold cyan]")
    if not findings:
        console.print(f"[yellow]No {domain} behavior found.[/yellow]")
        return
    by_confidence = result.get("by_confidence")
    by_confidence = by_confidence if isinstance(by_confidence, dict) else {}
    console.print(
        f"{result.get('count', len(findings))} findings,"
        f" high {by_confidence.get('high', 0)}, medium {by_confidence.get('medium', 0)}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Confidence", style="cyan")
    table.add_column("Kind")
    table.add_column("Name")
    table.add_column("Detail")
    for finding in findings:
        table.add_row(
            str(finding.get("confidence", "")),
            str(finding.get("kind", "")),
            str(finding.get("name", "")),
            str(finding.get("detail", "")),
        )
    console.print(table)


@app.command("behavior")
def behavior_command(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    domain: str | None = typer.Argument(
        None, help="Behavior domain: execution, networking or filesystem"
    ),
    all_domains: bool = typer.Option(False, "--all", help="Run all three behavior domains"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan a binary's execution, networking or filesystem behavior."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if domain is None and not all_domains:
        _fail("provide a behavior domain or --all", json_output)
    if domain is not None and domain not in behavior.BEHAVIOR_DOMAINS:
        _fail(f"unknown behavior domain: {domain}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    domains = behavior.BEHAVIOR_DOMAINS if all_domains else (str(domain),)
    results: dict[str, dict[str, Any]] = {}
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            for name in domains:
                try:
                    results[name] = journal.journaled_scan(
                        conn,
                        log,
                        binary_id,
                        behavior.DOMAIN_SCAN_KINDS[name],
                        partial(
                            behavior.scan_domain,
                            conn,
                            binary_id=binary_id,
                            domain=name,
                            engine=engine,
                        ),
                    )
                except engines.EngineError as exc:
                    _fail(str(exc), json_output)

    if json_output:
        if all_domains:
            typer.echo(json.dumps(log.attach(results)))
        else:
            typer.echo(json.dumps(log.attach(results[domains[0]])))
        return
    _print_journal_action(log, json_output)
    for name in domains:
        _print_behavior(binary_id, name, results[name])


# ── hardening ──────────────────────────────────────────────────────


def _print_hardening(binary_id: int, domain: str, result: dict[str, Any]) -> None:
    """Print one hardening scan's confidence counts, likelihood and findings table."""
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    console.print(f"\n[bold cyan]binary {binary_id} {domain}[/bold cyan]")
    by_confidence = result.get("by_confidence")
    by_confidence = by_confidence if isinstance(by_confidence, dict) else {}
    if domain == hardening.DOMAIN_OBFUSCATION:
        console.print(f"packer likelihood: [bold]{result.get('packer_likelihood', 'low')}[/bold]")
    if not findings:
        console.print(f"[yellow]No {domain} findings.[/yellow]")
    else:
        console.print(
            f"{result.get('count', len(findings))} findings,"
            f" high {by_confidence.get('high', 0)}, medium {by_confidence.get('medium', 0)}"
        )
        table = Table(show_header=True, header_style="bold")
        table.add_column("Confidence", style="cyan")
        table.add_column("Category")
        table.add_column("Name")
        table.add_column("Detail")
        for finding in findings:
            table.add_row(
                str(finding.get("confidence", "")),
                str(finding.get("category", "")),
                str(finding.get("name", "")),
                str(finding.get("detail", "")),
            )
        console.print(table)
    notes = result.get("notes")
    if isinstance(notes, list):
        for note in notes:
            console.print(f"[yellow]{note}[/yellow]")


@app.command("hardening")
def hardening_command(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    domain: str | None = typer.Argument(
        None, help="Hardening domain: anti-analysis or obfuscation"
    ),
    all_domains: bool = typer.Option(False, "--all", help="Run both hardening domains"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan a binary's anti-analysis or obfuscation surface."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if domain is None and not all_domains:
        _fail("provide a hardening domain or --all", json_output)
    if domain is not None and domain not in hardening.HARDENING_DOMAINS:
        _fail(f"unknown hardening domain: {domain}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    domains = hardening.HARDENING_DOMAINS if all_domains else (str(domain),)
    results: dict[str, dict[str, Any]] = {}
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            for name in domains:
                try:
                    results[name] = journal.journaled_scan(
                        conn,
                        log,
                        binary_id,
                        hardening.DOMAIN_SCAN_KINDS[name],
                        partial(
                            hardening.scan_hardening,
                            conn,
                            binary_id=binary_id,
                            domain=name,
                            engine=engine,
                        ),
                    )
                except engines.EngineError as exc:
                    _fail(str(exc), json_output)

    if json_output:
        if all_domains:
            typer.echo(json.dumps(log.attach(results)))
        else:
            typer.echo(json.dumps(log.attach(results[domains[0]])))
        return
    _print_journal_action(log, json_output)
    for name in domains:
        _print_hardening(binary_id, name, results[name])


# ── security-scan ──────────────────────────────────────────────────


@app.command("security-scan")
def security_scan(
    binary_id: int = typer.Argument(..., help="Binary id to scan"),
    min_severity: str = typer.Option(
        engines.DEFAULT_SECURITY_MIN_SEVERITY,
        "--min-severity",
        help="Minimum severity to report: high, medium or low",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Scan a binary's rebrew reversed sources for unsafe API use."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    if min_severity not in engines.SECURITY_SEVERITIES:
        _fail(f"unknown severity: {min_severity}", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        try:
            result = engine.security_scan(project_dir, min_severity)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_SECURITY, result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    if not findings:
        console.print("[yellow]No security findings.[/yellow]")
        return
    by_severity = result.get("by_severity")
    by_severity = by_severity if isinstance(by_severity, dict) else {}
    console.print(
        f"{result.get('count', len(findings))} findings across"
        f" {result.get('files_scanned', 0)} files,"
        f" high {by_severity.get('high', 0)}, medium {by_severity.get('medium', 0)},"
        f" low {by_severity.get('low', 0)}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", style="cyan")
    table.add_column("Rule")
    table.add_column("CWE")
    table.add_column("Location", style="magenta")
    table.add_column("Function")
    table.add_column("Snippet")
    for finding in findings:
        table.add_row(
            str(finding.get("severity", "")),
            str(finding.get("rule", "")),
            str(finding.get("cwe", "")),
            f"{finding.get('file', '')}:{finding.get('line', '')}",
            str(finding.get("function", "")),
            str(finding.get("snippet", "")),
        )
    console.print(table)


# ── threat ─────────────────────────────────────────────────────────


def _render_threat(result: dict[str, Any], binary_id: int) -> None:
    """Human rendering of a threat report: summary, IOC counts and techniques."""
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    narrative = result.get("narrative")
    if isinstance(narrative, dict) and narrative.get("summary"):
        console.print(str(narrative["summary"]))
    counts = result.get("ioc_counts")
    counts = counts if isinstance(counts, dict) else {}
    iocs = result.get("iocs")
    iocs = iocs if isinstance(iocs, dict) else {}
    total = sum(
        int(counts.get(category, len(iocs.get(category) or [])))
        for category in threat.IOC_CATEGORIES
    )
    if total == 0:
        console.print("[yellow]No indicators of compromise.[/yellow]")
    else:
        ioc_table = Table(show_header=True, header_style="bold")
        ioc_table.add_column("Category", style="cyan")
        ioc_table.add_column("Count", justify="right")
        ioc_table.add_column("Sample")
        for category in threat.IOC_CATEGORIES:
            findings = iocs.get(category)
            findings = findings if isinstance(findings, list) else []
            sample = ", ".join(str(item.get("value", "")) for item in findings[:_IOC_SAMPLE_SHOWN])
            ioc_table.add_row(category, str(counts.get(category, len(findings))), sample)
        console.print(ioc_table)
    techniques = result.get("techniques")
    techniques = techniques if isinstance(techniques, list) else []
    if not techniques:
        console.print("[yellow]No ATT&CK techniques mapped.[/yellow]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("ID", style="cyan")
        table.add_column("Technique")
        table.add_column("Confidence")
        table.add_column("Evidence", justify="right")
        for technique in techniques:
            evidence = technique.get("evidence")
            evidence = evidence if isinstance(evidence, list) else []
            table.add_row(
                str(technique.get("id", "")),
                str(technique.get("name", "")),
                str(technique.get("confidence", "")),
                str(len(evidence)),
            )
        console.print(table)
    notes = result.get("notes")
    if isinstance(notes, list):
        for note in notes:
            console.print(f"[dim]{note}[/dim]")


@app.command("threat")
def threat_command(
    binary_id: int = typer.Argument(..., help="Binary id to report on"),
    narrative: bool = typer.Option(
        False, "--narrative", help="Ask the configured LLM for an analyst summary"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build a local threat report: IOCs, ATT&CK techniques and an optional summary."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_THREAT,
                lambda: threat.build_threat_report(
                    conn,
                    binary_id=binary_id,
                    engine=engine,
                    llm_client=llm.get_client(),
                    narrative=narrative,
                ),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _render_threat(result, binary_id)


# ── yara, snort and stix ───────────────────────────────────────────


def _print_yara_summary(result: dict[str, Any]) -> None:
    """Write a rule's specificity and literal counts to stderr."""
    typer.echo(
        f"specificity: {result['specificity']},"
        f" {result['string_count']} strings, {result['import_count']} imports",
        err=True,
    )


def _build_remediation(binary_id: int, json_output: bool) -> tuple[journal.Journal, dict[str, Any]]:
    """Generate and store a binary's remediation payload, failing through :func:`_fail`."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_REMEDIATION,
                lambda: remediation.build_remediation(conn, binary_id=binary_id, engine=engine),
            )
        except remediation.NoStringsError as exc:
            _fail(str(exc), json_output)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
    return log, result


def _snort_artifact(result: dict[str, Any]) -> dict[str, Any]:
    """Return the Snort sub-object of a remediation payload, else an empty one."""
    snort = result.get("snort")
    return snort if isinstance(snort, dict) else {"rules": [], "text": "", "notes": []}


def _stix_artifact(result: dict[str, Any]) -> dict[str, Any]:
    """Return the STIX sub-object of a remediation payload, else an empty one."""
    stix = result.get("stix")
    return stix if isinstance(stix, dict) else {}


def _remediation_text(result: dict[str, Any], fmt: str) -> str:
    """Render one remediation artifact as the text its command prints."""
    if fmt == "yara":
        return str(result["rule"])
    if fmt == "snort":
        return str(_snort_artifact(result).get("text") or "")
    return remediation.as_json(_stix_artifact(result))


@app.command("yara")
def yara_command(
    binary_id: int = typer.Argument(..., help="Binary id to generate a rule for"),
    output: Path | None = typer.Option(None, "--output", help="Write the rule to this path"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate a YARA rule from a binary and store it as the remediation scan."""
    log, result = _build_remediation(binary_id, json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    if output is not None:
        typer.echo(str(_write_text_atomic(output.expanduser(), str(result["rule"]))))
        _print_yara_summary(result)
        return
    typer.echo(str(result["rule"]), nl=False)
    _print_yara_summary(result)


@app.command("snort")
def snort_command(
    binary_id: int = typer.Argument(..., help="Binary id to generate Snort rules for"),
    output: Path | None = typer.Option(None, "--output", help="Write the rules to this path"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate Snort rules from a binary's threat indicators and store the remediation scan."""
    log, result = _build_remediation(binary_id, json_output)
    artifact = _snort_artifact(result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    text = _remediation_text(result, "snort")
    if output is not None:
        typer.echo(str(_write_text_atomic(output.expanduser(), text)))
    elif text:
        typer.echo(text, nl=False)
    for note in artifact.get("notes") or []:
        typer.echo(str(note), err=True)
    typer.echo(f"{len(artifact.get('rules') or [])} Snort rules", err=True)


@app.command("stix")
def stix_command(
    binary_id: int = typer.Argument(..., help="Binary id to generate a STIX bundle for"),
    output: Path | None = typer.Option(None, "--output", help="Write the bundle to this path"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate a STIX 2.1 bundle from the binary's indicators and store the scan."""
    log, result = _build_remediation(binary_id, json_output)
    artifact = _stix_artifact(result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    text = _remediation_text(result, "stix")
    if output is not None:
        typer.echo(str(_write_text_atomic(output.expanduser(), text)))
    else:
        typer.echo(text, nl=False)
    objects = artifact.get("objects")
    count = len(objects) if isinstance(objects, list) else 0
    indicators = [
        obj
        for obj in (objects if isinstance(objects, list) else [])
        if isinstance(obj, dict) and obj.get("type") == "indicator"
    ]
    typer.echo(f"{len(indicators)} STIX indicators in {count} objects", err=True)


# ── triage ─────────────────────────────────────────────────────────


def _dossier_rows(dossier: dict[str, Any]) -> list[tuple[str, str]]:
    """Human field/value rows from a triage dossier's meta, toolchain and counts."""
    meta = dossier.get("meta")
    meta = meta if isinstance(meta, dict) else {}
    toolchain = dossier.get("toolchain")
    toolchain = toolchain if isinstance(toolchain, dict) else {}
    rows: list[tuple[str, str]] = []
    for field in _TRIAGE_META_FIELDS:
        if field not in meta:
            continue
        value = meta[field]
        if field in _TRIAGE_HEX_FIELDS and isinstance(value, int) and not isinstance(value, bool):
            rows.append((field, hex(value)))
        else:
            rows.append((field, str(value)))
    family = str(toolchain.get("family") or "")
    hint = str(toolchain.get("version_hint") or "")
    if family or hint:
        rows.append(("toolchain", f"{family} {hint}".strip()))
    for section in _TRIAGE_COUNT_SECTIONS:
        data = dossier.get(section)
        if not isinstance(data, dict):
            continue
        count = data.get("count", data.get("total"))
        if isinstance(count, int) and not isinstance(count, bool):
            rows.append((section, str(count)))
    return rows


@app.command()
def triage(
    binary_id: int = typer.Argument(..., help="Binary id to triage"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Run the engine's one-shot dossier for a binary and store it."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            _fail(f"no binary with id {binary_id}", json_output)
        path = Path(str(binary["path"]))
        if not path.is_file():
            _fail(f"binary {binary_id} has no readable file at {path}", json_output)
        try:
            dossier = engine.analyze(path)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_TRIAGE, dossier)

    if json_output:
        typer.echo(json.dumps(log.attach(dossier)))
        return
    _print_journal_action(log, json_output)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for field, value in _dossier_rows(dossier):
        table.add_row(field, value)
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    console.print(table)


# ── function triage ────────────────────────────────────────────────


def _print_function_triage(result: dict[str, Any], binary_id: int) -> None:
    """Print a function-triage run's model/method line and scored table."""
    entries = result.get("functions")
    entries = entries if isinstance(entries, list) else []
    by_method = result.get("by_method")
    by_method = by_method if isinstance(by_method, dict) else {}
    llm_count = int(by_method.get(function_triage.METHOD_LLM, 0) or 0)
    heuristic_count = int(by_method.get(function_triage.METHOD_HEURISTIC, 0) or 0)
    model = str(result.get("model") or "")
    console.print(
        f"\n[bold cyan]binary {binary_id}[/bold cyan]"
        f" (model {model or 'none'}, llm {llm_count}, heuristic {heuristic_count})"
    )
    if not entries:
        console.print("[yellow]No functions triaged.[/yellow]")
    else:
        show_capabilities = any(entry.get("capabilities") for entry in entries)
        table = Table(show_header=True, header_style="bold")
        table.add_column("Score", justify="right", style="magenta")
        table.add_column("Name", style="cyan")
        table.add_column("VA", style="magenta")
        table.add_column("Size", justify="right")
        table.add_column("Status")
        if show_capabilities:
            table.add_column("Capabilities")
        table.add_column("Summary")
        for entry in entries:
            capabilities = entry.get("capabilities")
            capabilities = capabilities if isinstance(capabilities, list) else []
            row = [
                f"{float(entry.get('score', 0.0)):.2f}",
                str(entry.get("name", "")),
                hex(int(entry.get("va", 0))),
                str(entry.get("size", 0)),
                str(entry.get("status", "")),
            ]
            if show_capabilities:
                row.append(", ".join(str(tag) for tag in capabilities))
            row.append(str(entry.get("summary", "")))
            table.add_row(*row)
        console.print(table)
    skipped = result.get("skipped")
    if isinstance(skipped, list) and skipped:
        console.print(f"[yellow]{len(skipped)} functions skipped.[/yellow]")
    notes = result.get("notes")
    if isinstance(notes, list):
        for note in notes:
            console.print(f"[yellow]{escape(str(note))}[/yellow]")


@app.command("function-triage")
def function_triage_command(
    binary_id: int = typer.Argument(..., help="Binary id whose functions to triage"),
    limit: int = typer.Option(
        function_triage.DEFAULT_LIMIT,
        "--limit",
        help="Maximum candidate functions to summarize",
    ),
    function: list[int] | None = typer.Option(
        None, "--function", help="Only triage this function id (repeatable)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Summarize and score a binary's high-value functions, storing the result.

    Without a configured LLM endpoint the run falls back to the deterministic
    heuristic score and a metadata summary derived from each function's stored
    rows.
    """
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_FUNCTION_TRIAGE,
                lambda: function_triage.summarize_functions(
                    conn,
                    binary_id=binary_id,
                    function_ids=function,
                    limit=limit,
                    client=llm.get_client(),
                    engine=engines.get_engine(),
                ),
            )
        except ValueError as exc:
            _fail(str(exc), json_output)
        except engines.EngineUnavailable as exc:
            _fail(f"rebrew engine unavailable: {exc}", json_output)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    _print_function_triage(result, binary_id)


# ── report ─────────────────────────────────────────────────────────


def _print_report_summary(summary: dict[str, Any]) -> None:
    """Print a report's coverage summary as a Rich table."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    for field in _REPORT_SUMMARY_FIELDS:
        if field in summary:
            table.add_row(field, str(summary[field]))
    status_counts = summary.get("status_counts")
    if isinstance(status_counts, dict):
        for status, count in status_counts.items():
            table.add_row(f"status {status}", str(count))
    console.print(table)


@app.command()
def report(
    binary_id: int = typer.Argument(..., help="Binary id to report on"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate a binary's rebrew HTML report into the workspace and store it."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        try:
            output_dir = reports_dir(binary_id)
        except WorkspaceNotFound as exc:
            _fail(str(exc), json_output)
        try:
            result = engine.report(project_dir, output_dir)
        except engines.EngineError as exc:
            _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_REPORT, result)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    summary = result.get("summary")
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    console.print(f"report: {result.get('out', '')}")
    _print_report_summary(summary if isinstance(summary, dict) else {})


@app.command("report-pdf")
def report_pdf(
    binary_id: int = typer.Argument(..., help="Binary id to report on"),
    output: Path | None = typer.Option(None, "--output", help="Write the PDF to this path"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
    queue: bool = typer.Option(False, "--queue", help="Queue the render instead of waiting for it"),
    status: bool = typer.Option(False, "--status", help="Report the stored PDF and its last job"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Render a binary's PDF summary from its stored scans, or queue it or read its status."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        if status:
            job = jobs.latest_job(conn, kind="report-pdf", binary_id=binary_id)
            try:
                target = reports_dir(binary_id) / pdf.REPORT_PDF_NAME
            except WorkspaceNotFound as exc:
                _fail(str(exc), json_output)
            payload = {
                "binary_id": binary_id,
                "exists": target.is_file(),
                "path": str(target),
                "bytes": target.stat().st_size if target.is_file() else 0,
                "pages": (job or {}).get("result", {}).get("pages", 0) if job else 0,
                "job": job,
            }
            if json_output:
                typer.echo(json.dumps(payload))
                return
            console.print(f"pdf: {'present' if payload['exists'] else 'absent'} {payload['path']}")
            if job:
                console.print(f"job {job['id']}: {job['status']} {job['error']}".rstrip())
            return
        if queue:
            job = jobs.submit(conn, kind="report-pdf", binary_id=binary_id)
            if json_output:
                typer.echo(json.dumps(job))
                return
            console.print(f"job {job['id']}: {job['status']}")
            return
        if output is not None:
            target = output.expanduser()
            if target.exists() and not force:
                _fail(f"{target} exists (pass --force to overwrite)", json_output)
        else:
            try:
                target = reports_dir(binary_id) / pdf.REPORT_PDF_NAME
            except WorkspaceNotFound as exc:
                _fail(str(exc), json_output)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            result = pdf.write_report(conn, binary_id=binary_id, path=target, generated=store.now())
            journal.journaled_file(log, target, previous=previous)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    console.print(
        f"[green]Wrote[/green] {result['bytes']} bytes, {result['pages']} page(s)"
        f" to {result['path']}"
    )
    console.print(f"Sections: {', '.join(result['sections']) or 'none'}")


# ── unstrip ────────────────────────────────────────────────────────


@app.command("unstrip")
def unstrip_command(
    binary_id: int = typer.Argument(..., help="Binary id to identify library functions for"),
    min_confidence: float = typer.Option(
        unstrip.DEFAULT_MIN_CONFIDENCE,
        "--min-confidence",
        help="Minimum engine confidence a proposal must reach",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Store rename proposals for a binary's library-identified functions."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    engine = engines.get_engine()
    if not engine.available():
        _fail(f"rebrew engine unavailable: {engines.ENGINE_UNAVAILABLE_HINT}", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        if store.get_binary(conn, binary_id) is None:
            _fail(f"no binary with id {binary_id}", json_output)
        if store.get_rebrew_context(conn, binary_id) is None:
            _fail(
                f"binary {binary_id} has no rebrew project context"
                " (run 'reportal import-rebrew <project-dir>')",
                json_output,
            )
        try:
            log, result = _run_scan_command(
                conn,
                binary_id,
                store.SCAN_KIND_UNSTRIP,
                lambda: unstrip.run_unstrip(
                    conn, binary_id=binary_id, engine=engine, min_confidence=min_confidence
                ),
            )
        except engines.EngineError as exc:
            _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(log.attach(result)))
        return
    _print_journal_action(log, json_output)
    proposals = result["proposals"]
    console.print(f"\n[bold cyan]binary {binary_id}[/bold cyan]")
    console.print(f"{result['candidates']} candidates, {len(proposals)} proposals")
    if not proposals:
        console.print("[yellow]No unstrip proposals.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("VA", style="magenta")
    table.add_column("Current", style="cyan")
    table.add_column("Proposed", style="green")
    table.add_column("Module")
    table.add_column("Kind")
    table.add_column("Conf", justify="right")
    for proposal in proposals:
        table.add_row(
            hex(proposal["va"]),
            proposal["current_name"],
            proposal["proposed_name"],
            proposal["module"],
            proposal["kind"],
            f"{proposal['confidence']:.2f}",
        )
    console.print(table)


@app.command("unstrip-apply")
def unstrip_apply(
    function_id: int = typer.Argument(..., help="Function id to rename from its stored proposal"),
    name: str | None = typer.Option(None, "--name", help="Override the proposed name"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Apply one stored unstrip proposal, recording the rename in history."""
    portal_db = _db_path(json_output)
    if not portal_db.exists():
        _fail(f"no reportal database at {portal_db} (run 'reportal init')", json_output)
    with contextlib.closing(store.connect(portal_db)) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                change = journal.journaled_name_change(
                    conn,
                    log,
                    function_id,
                    lambda: unstrip.apply_proposal(conn, function_id=function_id, new_name=name),
                )
            except KeyError:
                _fail(f"no function with id {function_id}", json_output)
            except unstrip.NoProposalError as exc:
                _fail(str(exc), json_output)
            except ValueError as exc:
                _fail(str(exc), json_output)
        payload = log.attach(change)

    if json_output:
        typer.echo(json.dumps(payload))
    else:
        console.print(
            f"[green]Renamed[/green] function {function_id}:"
            f" {change['old_name']!r} -> {change['new_name']!r}"
        )
    _print_journal_action(log, json_output)


# ── import-rebrew ──────────────────────────────────────────────────


class _ImportError(Exception):
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
        raise _ImportError(f"no coverage.db at {db_file}")
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


def _sha256_file(path: Path) -> str:
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
        raise _ImportError("coverage.db functions table has no va column")
    wanted = ["va"] + [c for c in ("name", "size", "status", "module") if c in columns]
    sql = f"SELECT {', '.join(wanted)} FROM functions WHERE target = ?"
    if "markerType" in columns:
        sql += " AND markerType NOT IN ('GLOBAL', 'DATA')"
    return [
        {
            "va": int(row["va"]),
            "name": str(row["name"] or ""),
            "size": int(row["size"] or 0),
            "status": str(row["status"] or "unknown"),
        }
        for row in conn.execute(sql, (target,)).fetchall()
    ]


def _functions_from_cells(conn: sqlite3.Connection, target: str) -> list[dict[str, Any]]:
    """Synthesize function rows from rebrew's ``cells`` table.

    Used when a coverage.db has no ``functions`` table: each non-empty cell
    becomes one function at the cell start, named from the cell's function
    list when present.
    """
    columns = _table_columns(conn, "cells")
    if not {"start", "state"} <= columns:
        raise _ImportError("coverage.db cells table has no start/state columns")
    has_end = "end" in columns
    has_functions = "functions" in columns
    selected = ", ".join(
        ["start", "state"] + (["end"] if has_end else []) + (["functions"] if has_functions else [])
    )
    functions: list[dict[str, Any]] = []
    for row in conn.execute(
        f"SELECT {selected} FROM cells WHERE target = ? AND state != 'none'", (target,)
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
                "name": name or f"sub_{va:x}",
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


def run_import_rebrew(project_dir: Path) -> dict[str, Any]:
    """Ingest a rebrew workspace into the portal database; returns a summary.

    Idempotent: a binary is identified by content hash (or name+path when the
    binary is absent), its import analysis is reused, and functions are
    upserted by VA, so a second run refreshes rows instead of duplicating.
    Each binary records the resolved project directory as its rebrew context,
    which disassembly reads back; storing it is not engine-gated.  The target
    binary's import stubs are ingested on top, best effort, as already-named
    THUNK rows that never replace a coverage-db row.
    Raises :class:`_ImportError` for a missing or unrecognized workspace.
    """
    project_dir = project_dir.expanduser().resolve()
    rebrew_db = _resolve_rebrew_db(project_dir)
    binaries_map = _target_binaries(project_dir)

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
        tables = {
            str(row[0])
            for row in coverage.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        source = next((t for t in ("functions", "cells", "metadata") if t in tables), None)
        if source is None:
            raise _ImportError(
                f"unrecognized coverage.db schema at {rebrew_db} "
                "(no functions, cells or metadata table)"
            )
        targets = _rebrew_targets(coverage, source)
        if not targets:
            raise _ImportError(f"{rebrew_db} contains no targets")

        with contextlib.closing(store.connect(portal_db)) as portal:
            for target in targets:
                functions = _collect_rebrew_functions(coverage, target, source)
                binary_path = binaries_map.get(target)
                sha256 = _sha256_file(binary_path) if binary_path else None
                binary_id = store.add_binary(
                    portal,
                    sha256=sha256,
                    name=target,
                    path=str(binary_path) if binary_path else "",
                    size=binary_path.stat().st_size if binary_path else 0,
                    fmt=binary_path.suffix.lstrip(".").upper() if binary_path else "",
                )
                store.set_rebrew_context(portal, binary_id, str(project_dir))
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
                    }
                )
                summary["created_functions"] += created
                summary["updated_functions"] += updated
                summary["stubs"] += stubs

    return summary


@app.command("import-rebrew")
def import_rebrew(
    project_dir: Path = typer.Argument(..., help="Path to a rebrew workspace"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Import a rebrew workspace: register its target binaries, functions and import stubs."""
    if not project_dir.is_dir():
        _fail(f"not a directory: {project_dir}", json_output)
    try:
        summary = run_import_rebrew(project_dir)
    except (_ImportError, WorkspaceNotFound) as exc:
        _fail(str(exc), json_output)

    if json_output:
        typer.echo(json.dumps(summary))
        return
    console.print(f"[green]Imported[/green] {summary['project']}")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Target", style="cyan")
    table.add_column("Binary ID", justify="right")
    table.add_column("Functions", justify="right")
    table.add_column("Created", justify="right", style="green")
    table.add_column("Updated", justify="right", style="yellow")
    table.add_column("Stubs", justify="right")
    for entry in summary["targets"]:
        table.add_row(
            entry["name"],
            str(entry["binary_id"]),
            str(entry["functions"]),
            str(entry["created"]),
            str(entry["updated"]),
            str(entry["stubs"]),
        )
    console.print(table)


def main() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main()

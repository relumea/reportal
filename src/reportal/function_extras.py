"""The per-function extras: indirect call sites, capabilities, edges and names.

The hosted portal carries a set of function-level reads and writes on top of the
decompilation it already stores:

* indirect call sites (`GET /v3/functions/{id}/indirect-call-sites`) and the
  callers and callees of many functions at once (`GET
  /v3/functions/callees-callers`);
* per-function capabilities (`GET /v3/functions/{id}/capabilities`);
* analyst-declared callee edges (`POST /v3/functions/{id}/callees`);
* name canonicalisation over a batch (`POST /v3/functions/canonical-names`);
* matching over an explicit function set (`GET|POST /v3/functions/matches`).

Everything here is derived from rows reportal already holds.  No engine call is
made and no model is asked: the disassembly comes from `disasm_cache` when the
function has one (a function with no cached listing reports that, rather than
spawning the engine behind a read), the callees and capabilities come from a
text scan of the stored decompilation, the canonical name comes from a record
the store already has (a predicted name, else the last recorded rename), and a
match read answers the recorded `matches` rows.  Every payload carries the
``derivation`` note saying so, because a text scan is not engine output and a
recorded match is not a fresh score.

An analyst-declared edge is the one thing here that is *not* derived: it is a
row in :data:`EDGE_TABLE`, written on request and journaled like every other
write, so an analyst can record "this call goes to the dispatch table" when the
engine cannot.
"""

from __future__ import annotations

import re
import sqlite3
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from reportal import capabilities, journal, store

# The table the analyst edges live in (created on first use).
EDGE_TABLE = "function_edges"

# An edge's kind: a direct call, or one made through a pointer.
EDGE_CALL = "call"
EDGE_INDIRECT = "indirect"
EDGE_KINDS: tuple[str, ...] = (EDGE_CALL, EDGE_INDIRECT)

# The source every edge recorded here carries, so a reader can tell an analyst's
# claim from a scan.
EDGE_SOURCE_ANALYST = "analyst"

# Bounds: a bounded id list per read, a bounded edge list per function, and a
# bounded name and note.
MAX_FUNCTIONS_PER_QUERY = 50
MAX_EDGES_PER_FUNCTION = 200
MAX_CALLEE_NAME_CHARS = 128
MAX_NOTE_CHARS = 500

# Where the derived entries came from, and the note every payload carries.
DERIVATION = (
    "derived from rows reportal already stored: the cached disassembly, the"
    " stored decompilation and the recorded matches; no engine run and no model"
    " call"
)
CALL_SITE_NOTE = (
    "an indirect call is a call instruction whose operand is a register or a"
    " memory reference rather than a direct address; the scan reads the cached"
    " listing, so a function with no cached disassembly reports no sites rather"
    " than running the engine"
)
MATCH_NOTE = (
    "the recorded match rows of each function, with the derived metrics; this"
    " read runs no scoring and no engine"
)
CANONICAL_NOTE = (
    "the canonical name is the candidate the store already recorded for the"
    " function (a predicted name, else the last recorded rename); a function with"
    " no candidate is skipped rather than renamed to a guess"
)

# Error codes the surface reports, shared by the API, CLI and MCP.
ERROR_INVALID = "invalid edge"
ERROR_NOT_FOUND = "edge not found"

# The instruction forms that make a call indirect.  The listing is `nasm`, so a
# direct call is `call 0x401000` or `call sub_401000` and everything else is a
# register or a memory operand.
_CALL_RE = re.compile(r"^\s*[0-9a-f]{4,}\s+(call|jmp)\s+(?P<target>.+?)\s*$", re.IGNORECASE)
# A direct target: a hex address, a named symbol, or an import stub.  A register
# name matches the identifier shape too, so the register vocabulary below is
# what separates a register operand from a symbol.
_DIRECT_TARGET_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[A-Za-z_.][\w.$@?]*)$")
_REGISTERS = frozenset(
    {
        *(f"r{index}" for index in range(8, 16)),
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "rip",
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "esp",
        "eip",
        "ax",
        "bx",
        "cx",
        "dx",
        "si",
        "di",
        "bp",
        "sp",
        "al",
        "bl",
        "cl",
        "dl",
        "ah",
        "bh",
        "ch",
        "dh",
        "sil",
        "dil",
        "bpl",
        "spl",
        "r8b",
        "r9b",
        "r10b",
        "r11b",
        "r12b",
        "r13b",
        "r14b",
        "r15b",
        "r8w",
        "r9w",
        "r10w",
        "r11w",
        "r12w",
        "r13w",
        "r14w",
        "r15w",
        "r8d",
        "r9d",
        "r10d",
        "r11d",
        "r12d",
        "r13d",
        "r14d",
        "r15d",
    }
)
# A C identifier, for the callee and import scans.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS function_edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    callee_name TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'call',
    note        TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'analyst',
    created_at  TEXT NOT NULL
);
-- Unique ``(function_id, callee_name, kind)`` replaces the plain function index
-- and stops a concurrent re-declare from inserting a duplicate edge.  The
-- leftmost prefix still covers per-function listings.
DROP INDEX IF EXISTS idx_function_edges_function;
CREATE UNIQUE INDEX IF NOT EXISTS idx_function_edges_function_callee_kind
    ON function_edges(function_id, callee_name, kind);
"""


class EdgeError(Exception):
    """Base class for a rejected analyst-edge operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class InvalidEdgeError(EdgeError, ValueError):
    """A callee name, kind or note is unusable; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_INVALID, detail)


class UnknownEdgeError(EdgeError, LookupError):
    """No edge carries the requested id; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NOT_FOUND, detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the edge table when the database predates it."""
    conn.executescript(_SCHEMA)


# ── Derivations over stored text ───────────────────────────────────


def indirect_call_sites(
    disassembly: str, *, limit: int = MAX_EDGES_PER_FUNCTION
) -> list[dict[str, Any]]:
    """The indirect calls and jumps in one listing, in listing order.

    A direct target (an address or a symbol) is left out; a register or memory
    operand is reported with its line number and the operand text, so a caller
    can see exactly which instruction the claim rests on.
    """
    sites: list[dict[str, Any]] = []
    for number, line in enumerate((disassembly or "").splitlines(), start=1):
        match = _CALL_RE.match(line)
        if match is None:
            continue
        target = match.group("target").strip()
        if not target or (target.lower() not in _REGISTERS and _DIRECT_TARGET_RE.match(target)):
            continue
        sites.append(
            {
                "line": number,
                "kind": "indirect",
                "mnemonic": match.group(1).lower(),
                "target": target,
                "instruction": line.strip(),
            }
        )
        if len(sites) >= limit:
            break
    return sites


def callees_from_text(code: str, *, known: Mapping[str, int], exclude: str) -> list[dict[str, Any]]:
    """The functions *code* names, matched against the names the store knows.

    The match is a whole-token one against the binary's function names (and its
    import stubs), so a name mentioned in a comment counts the same as one in a
    call.  It is a text derivation and the payload says so; reportal stores no
    call graph, so the alternative would be an engine call per function.
    """
    found: dict[str, dict[str, Any]] = {}
    for match in _IDENTIFIER_RE.finditer(code or ""):
        name = match.group(0)
        if name == exclude or name not in known:
            continue
        entry = found.get(name)
        if entry is None:
            found[name] = {
                "name": name,
                "function_id": known[name],
                "derivation": "decompilation-text",
            }
    return list(found.values())


def capability_inputs(
    code: str, *, known_imports: Mapping[str, int]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The import and string entries a capability classification reads for *code*.

    An import entry is a name the binary imports and the decompilation mentions;
    a string entry is a quoted literal.  Both come from the stored text, which
    is what lets a per-function classification exist without an engine call.
    """
    imports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _IDENTIFIER_RE.finditer(code or ""):
        name = match.group(0)
        if name in seen or name not in known_imports:
            continue
        seen.add(name)
        imports.append({"name": name, "va": f"0x{known_imports[name]:x}"})
    strings = [{"text": text} for text in _quoted(code)]
    return imports, strings


_QUOTED_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def _quoted(code: str) -> list[str]:
    """The quoted literals in *code*, deduped, in first-seen order."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _QUOTED_RE.finditer(code or ""):
        text = match.group(1)
        if not text or text in seen:
            continue
        seen.add(text)
        found.append(text)
    return found


def _known_imports(conn: sqlite3.Connection, binary_id: int) -> dict[str, int]:
    """The binary's imported names mapped to their VA."""
    known: dict[str, int] = {}
    for function in store.list_functions(conn, binary_id=binary_id):
        if str(function.get("name_source") or "") != store.IMPORTED_NAME_SOURCE:
            continue
        name = str(function["name"] or "")
        if name and name not in known:
            known[name] = int(function["va"])
    return known


def function_capabilities(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Classify one function from its stored decompilation.

    The rule table is the one the binary-level scan uses
    (:func:`reportal.capabilities.classify`), fed with the imports and the string
    literals the function's own text mentions, so a function's capabilities and
    the binary's are the same vocabulary and cannot disagree about a rule.
    """
    function = store.get_function(conn, function_id)
    if function is None:
        raise UnknownEdgeError(f"no function with id {function_id}")
    binary_id = int(function["binary_id"])
    stored = store.get_decompilation(conn, function_id)
    code = str(stored["code"]) if stored is not None else ""
    imports, strings = capability_inputs(code, known_imports=_known_imports(conn, binary_id))
    found = capabilities.classify(imports, strings)
    return {
        "function_id": function_id,
        "capabilities": found,
        "count": len(found),
        "inputs": {"imports": len(imports), "strings": len(strings)},
        "has_decompilation": stored is not None,
        "derivation": (
            "classified from the imports and string literals this function's"
            " stored decompilation mentions, with the same rule table the"
            " binary-level scan uses"
        ),
    }


def canonical_candidate(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """The canonical name the store already recorded for a function, or None.

    A predicted name (the pipeline's `predicted-name` artifact) wins, then the
    newest recorded rename; a function with neither has no candidate, which the
    caller reports as skipped rather than inventing one.
    """
    function = store.get_function(conn, function_id)
    if function is None:
        raise UnknownEdgeError(f"no function with id {function_id}")
    predicted = store.get_ai_artifact(conn, function_id, "predicted-name")
    if predicted is not None:
        payload = predicted["payload"]
        name = payload.get("name") if isinstance(payload, Mapping) else None
        if isinstance(name, str) and name.strip():
            return {
                "name": name.strip(),
                "source": "predicted-name",
                "confidence": payload.get("confidence"),
            }
    for entry in store.list_name_history(conn, function_id):
        name = str(entry.get("new_name") or "").strip()
        if name:
            return {"name": name, "source": str(entry.get("source") or "rename")}
    return None


def canonical_names(
    conn: sqlite3.Connection,
    function_ids: Sequence[int],
    *,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The canonical candidate of each requested function; writes nothing.

    The caller renames through :func:`reportal.journal.journaled_name_change`, so
    this only decides what the candidate is and reports the ones that have none.
    ``visible_to`` reports a function on a hidden binary as not found, like
    the other batch reads, so the plan never names what the caller may not see.
    """
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    visible: set[int] | None = None
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    ids = [int(function_id) for function_id in function_ids]
    functions = store.functions_by_ids(conn, ids)
    for function_id in ids:
        function = functions.get(function_id)
        if function is None or (visible is not None and int(function["binary_id"]) not in visible):
            skipped.append({"function_id": function_id, "reason": "not found"})
            continue
        candidate = canonical_candidate(conn, function_id)
        if candidate is None:
            skipped.append(
                {"function_id": function_id, "reason": "no canonical candidate recorded"}
            )
            continue
        current = str(function["name"] or "")
        applied.append(
            {
                "function_id": function_id,
                "from": current,
                "to": candidate["name"],
                "source": candidate["source"],
                "changed": candidate["name"] != current,
            }
        )
    return {"planned": applied, "skipped": skipped, "count": len(applied), "note": CANONICAL_NOTE}


def _visible_binary_ids(
    conn: sqlite3.Connection, visible_to: Mapping[str, Any] | None
) -> set[int] | None:
    """The binary ids *visible_to* may see, or None for no restriction.

    None means "no restriction": auth is off (the local operator sees the
    whole workspace) or the caller is an admin.  Otherwise a function of a
    team binary the caller is not in reads as missing, the same 404-as-absent
    the per-object gate reports, so a batch read cannot leak what a single
    read refuses.
    """
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is None:
        return None
    clause, params = scope
    rows = conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params).fetchall()
    return {int(row["id"]) for row in rows}


def match_rows(
    conn: sqlite3.Connection,
    function_ids: Sequence[int],
    *,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The recorded match rows of each function, in the caller's order.

    The metrics are the same derived pair the single-function route reports
    (`difference` and `band`), so a batch read and a single read cannot disagree.
    A function of a binary *visible_to* may not see reads as missing, like the
    per-object gate.
    """
    from reportal import composition, matching

    visible = _visible_binary_ids(conn, visible_to)
    ids = [int(function_id) for function_id in function_ids]
    functions = store.functions_by_ids(conn, ids)
    matches_by_function = store.list_matches_for_functions(conn, list(functions))
    rows: list[dict[str, Any]] = []
    for function_id in ids:
        function = functions.get(function_id)
        if function is None or (visible is not None and int(function["binary_id"]) not in visible):
            rows.append({"function_id": function_id, "found": False, "matches": []})
            continue
        matches = []
        for row in matches_by_function.get(function_id, ()):
            similarity_score = float(row.get("similarity") or 0.0)
            matches.append(
                {
                    **row,
                    "difference": matching.difference_of(similarity_score),
                    "band": composition.quality_band(similarity_score),
                }
            )
        rows.append(
            {
                "function_id": function_id,
                "found": True,
                "name": str(function["name"] or ""),
                "matches": matches,
                "count": len(matches),
            }
        )
    return {"functions": rows, "count": len(rows), "note": MATCH_NOTE}


# ── Analyst-declared edges ─────────────────────────────────────────


def normalize_callee(name: Any) -> str:
    """Validate a callee name, raising :class:`InvalidEdgeError`.

    The name is stripped and NFC-normalized so an NFD spelling cannot open a
    second edge row for the same logical callee under the unique
    ``(function_id, callee_name, kind)`` index.
    """
    if not isinstance(name, str) or not name.strip():
        raise InvalidEdgeError("callee must be a non-empty name")
    trimmed = unicodedata.normalize("NFC", name.strip())
    if len(trimmed) > MAX_CALLEE_NAME_CHARS:
        raise InvalidEdgeError(f"callee exceeds {MAX_CALLEE_NAME_CHARS} characters")
    return trimmed


def normalize_edge_kind(kind: Any) -> str:
    """Validate an edge kind, raising :class:`InvalidEdgeError`."""
    if kind in (None, ""):
        return EDGE_CALL
    if not isinstance(kind, str) or kind.strip() not in EDGE_KINDS:
        raise InvalidEdgeError(f"kind must be one of {', '.join(EDGE_KINDS)}")
    return kind.strip()


def normalize_note(note: Any) -> str:
    """Validate an optional edge note, raising :class:`InvalidEdgeError`."""
    if note is None:
        return ""
    if not isinstance(note, str):
        raise InvalidEdgeError("note must be a string")
    trimmed = note.strip()
    if len(trimmed) > MAX_NOTE_CHARS:
        raise InvalidEdgeError(f"note exceeds {MAX_NOTE_CHARS} characters")
    return trimmed


def _edge_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One stored edge as the surfaces report it."""
    return {
        "id": int(row["id"]),
        "function_id": int(row["function_id"]),
        "callee": str(row["callee_name"]),
        "kind": str(row["kind"]),
        "note": str(row["note"]),
        "source": str(row["source"]),
        "created_at": str(row["created_at"]),
    }


def add_edge(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    callee: Any,
    kind: Any = None,
    note: Any = None,
) -> dict[str, Any]:
    """Record one analyst-declared callee edge, replacing an identical one.

    A row for the same ``(function, callee, kind)`` is updated in place (the
    note and the time move), so re-declaring an edge is not a duplicate.
    """
    ensure_schema(conn)
    if store.get_function(conn, function_id) is None:
        raise UnknownEdgeError(f"no function with id {function_id}")
    resolved_callee = normalize_callee(callee)
    resolved_kind = normalize_edge_kind(kind)
    resolved_note = normalize_note(note)
    existing = conn.execute(
        f"SELECT * FROM {EDGE_TABLE} WHERE function_id = ? AND callee_name = ? AND kind = ?",
        (function_id, resolved_callee, resolved_kind),
    ).fetchone()
    if existing is not None:
        conn.execute(
            f"UPDATE {EDGE_TABLE} SET note = ?, created_at = ? WHERE id = ?",
            (resolved_note, store.now(), int(existing["id"])),
        )
        conn.commit()
        return get_edge(conn, edge_id=int(existing["id"]))
    count = conn.execute(
        f"SELECT COUNT(*) AS n FROM {EDGE_TABLE} WHERE function_id = ?", (function_id,)
    ).fetchone()
    if count is not None and int(count["n"]) >= MAX_EDGES_PER_FUNCTION:
        raise InvalidEdgeError(f"a function holds at most {MAX_EDGES_PER_FUNCTION} edges")
    cursor = conn.execute(
        f"INSERT INTO {EDGE_TABLE} (function_id, callee_name, kind, note, source, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            function_id,
            resolved_callee,
            resolved_kind,
            resolved_note,
            EDGE_SOURCE_ANALYST,
            store.now(),
        ),
    )
    conn.commit()
    return get_edge(conn, edge_id=int(cursor.lastrowid or 0))


def get_edge(conn: sqlite3.Connection, *, edge_id: int) -> dict[str, Any]:
    """One stored edge by id; raises :class:`UnknownEdgeError`."""
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {EDGE_TABLE} WHERE id = ?", (int(edge_id),)).fetchone()
    if row is None:
        raise UnknownEdgeError(f"no edge with id {edge_id}")
    return _edge_row(row)


def list_edges(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """Every analyst-declared edge of one function, oldest first."""
    ensure_schema(conn)
    if store.get_function(conn, function_id) is None:
        raise UnknownEdgeError(f"no function with id {function_id}")
    return list_edges_for_functions(conn, [function_id]).get(int(function_id), [])


def list_edges_for_functions(
    conn: sqlite3.Connection, function_ids: Sequence[int]
) -> dict[int, list[dict[str, Any]]]:
    """Analyst-declared edges for many functions in one query, oldest first.

    Does not validate that the function ids exist; an unknown id is simply
    absent, which is what a batch reader that already resolved the functions
    wants.
    """
    ensure_schema(conn)
    if not function_ids:
        return {}
    ids = [int(function_id) for function_id in function_ids]
    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT * FROM {EDGE_TABLE} WHERE function_id IN ({placeholders}) ORDER BY id",
        ids,
    ).fetchall()
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(int(row["function_id"]), []).append(_edge_row(row))
    return grouped


def delete_edge(conn: sqlite3.Connection, function_id: int, *, edge_id: int) -> dict[str, Any]:
    """Remove one analyst edge from its function; 404 when it is not there."""
    row = get_edge(conn, edge_id=edge_id)
    if row["function_id"] != int(function_id):
        raise UnknownEdgeError(f"edge {edge_id} is not on function {function_id}")
    conn.execute(f"DELETE FROM {EDGE_TABLE} WHERE id = ?", (int(edge_id),))
    conn.commit()
    return row


def journaled_add_edge(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    function_id: int,
    callee: Any,
    kind: Any = None,
    note: Any = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Add one analyst edge inside the caller's journaled action."""
    probe = str(callee).strip() if isinstance(callee, str) else ""
    resolved_kind = normalize_edge_kind(kind)
    before = journal.journaled_rows(
        conn,
        log,
        table=EDGE_TABLE,
        where="function_id = ? AND callee_name = ? AND kind = ?",
        params=(int(function_id), probe, resolved_kind),
        description=description or f"replaced the {probe} edge of function {function_id}",
    )
    row = add_edge(conn, function_id=function_id, callee=callee, kind=kind, note=note)
    if not before:
        journal.journaled_create(
            log,
            table=EDGE_TABLE,
            key=int(row["id"]),
            description=description or f"recorded the {probe} edge of function {function_id}",
        )
    return row


def journaled_delete_edge(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    function_id: int,
    edge_id: int,
    description: str | None = None,
) -> dict[str, Any]:
    """Remove one analyst edge inside the caller's journaled action."""
    journal.journaled_rows(
        conn,
        log,
        table=EDGE_TABLE,
        where="id = ?",
        params=(int(edge_id),),
        description=description or f"removed edge {edge_id}",
    )
    return delete_edge(conn, function_id, edge_id=edge_id)


# ── The batch read ─────────────────────────────────────────────────


def callers_and_callees(
    conn: sqlite3.Connection,
    function_ids: Sequence[int],
    *,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Each requested function's derived callers and callees, in the caller's order.

    A callee is a name the function's stored decompilation mentions that the
    binary also stores as a function (or an import stub), plus every
    analyst-declared edge; a caller is a function whose text mentions this one.
    All of it is a text derivation over stored rows and the payload says so; a
    function with no stored decompilation reports empty lists rather than
    spawning the engine.  A function of a binary *visible_to* may not see
    reads as missing, like the per-object gate.
    """
    visible = _visible_binary_ids(conn, visible_to)
    ids = [int(function_id) for function_id in function_ids]
    functions = store.functions_by_ids(conn, ids)
    edges_by_function = list_edges_for_functions(conn, list(functions))

    # Per-binary caches so a batch over many functions of the same binary does
    # not re-list its functions or re-read every decompilation per request id.
    known_by_binary: dict[int, dict[str, int]] = {}
    peers_by_binary: dict[int, list[dict[str, Any]]] = {}
    decompilations_by_binary: dict[int, dict[int, dict[str, Any]]] = {}

    def _binary_context(
        binary_id: int,
    ) -> tuple[dict[str, int], list[dict[str, Any]], dict[int, dict[str, Any]]]:
        known = known_by_binary.get(binary_id)
        if known is None:
            peers = store.list_functions(conn, binary_id=binary_id)
            known = {}
            for peer in peers:
                peer_name = str(peer["name"] or "")
                if peer_name and peer_name not in known:
                    known[peer_name] = int(peer["id"])
            known_by_binary[binary_id] = known
            peers_by_binary[binary_id] = peers
            decompilations_by_binary[binary_id] = store.decompilations_for_binary(conn, binary_id)
        return known, peers_by_binary[binary_id], decompilations_by_binary[binary_id]

    rows: list[dict[str, Any]] = []
    for function_id in ids:
        function = functions.get(function_id)
        if function is None or (visible is not None and int(function["binary_id"]) not in visible):
            rows.append(
                {
                    "function_id": function_id,
                    "found": False,
                    "callers": [],
                    "callees": [],
                }
            )
            continue
        binary_id = int(function["binary_id"])
        known, peers, decompilations = _binary_context(binary_id)
        stored = decompilations.get(function_id)
        code = str(stored["code"]) if stored is not None else ""
        callees = callees_from_text(code, known=known, exclude=str(function["name"] or ""))
        declared = [
            {
                "name": entry["callee"],
                "kind": entry["kind"],
                "source": entry["source"],
                "edge_id": entry["id"],
            }
            for entry in edges_by_function.get(function_id, ())
        ]
        name = str(function["name"] or "")
        callers: list[dict[str, Any]] = []
        if name:
            for other in peers:
                other_id = int(other["id"])
                if other_id == function_id:
                    continue
                other_stored = decompilations.get(other_id)
                if other_stored is None:
                    continue
                if name == str(other["name"] or ""):
                    continue
                if any(
                    match.group(0) == name
                    for match in _IDENTIFIER_RE.finditer(str(other_stored["code"]))
                ):
                    callers.append(
                        {
                            "function_id": other_id,
                            "name": str(other["name"] or ""),
                            "derivation": "decompilation-text",
                        }
                    )
        rows.append(
            {
                "function_id": function_id,
                "found": True,
                "name": name,
                "callers": callers,
                "callees": callees,
                "declared": declared,
                "has_decompilation": stored is not None,
            }
        )
    return {
        "functions": rows,
        "count": len(rows),
        "derivation": DERIVATION,
        "note": CALL_SITE_NOTE,
    }

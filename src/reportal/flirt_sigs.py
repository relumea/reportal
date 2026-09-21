"""FLIRT signature catalog and the match cache in front of it.

A FLIRT signature set is a compiled ``.sig`` blob plus the metadata that says
what it covers.  Neither belongs in a table: the blobs are content-addressed
files on disk (one row per file, keyed by ``rel_path``), and the patterns stay
inside the blob.  The catalog is global rather than tenant-scoped, because a
signature set is a fact about a toolchain and every workspace sees the same
one; only what a tenant may read is scoped, and that happens at the response
seam.

Two caches make the difference between a usable matcher and an unusable one.

``sigset_key`` is a digest over the enabled ``.sig`` blobs of one
architecture.  It is the identity of "the signature library as it stood", so a
catalog refresh changes it and stale results never read as current.

``flirt_scan`` caches one binary's matches under
``(binary_sha256, sigset_key, arch)``.  Matching is deterministic and
independent of who asked, so a binary scanned once is never scanned again --
which is the whole win in a multi-tenant portal, where the same MSVC runtime
arrives from every user.  A catalog change moves the key; orphaned rows under
the previous digest are pruned so the table cannot grow one dead row per
refresh.

The engine itself (:func:`matcher_for`) is built once per process per key and
reused.  ``flirt.parse_sig``/``flirt.compile`` are the slow half, and
recompiling per request is what makes a naive FLIRT API unusable.  A ``.pat``
file is never parsed here: its parser is superlinear (seconds per megabyte)
against milliseconds for the compiled form.

Nothing here names or renames a function.  It reports matches; the library
scan (:mod:`reportal.library`) and the rename paths own what happens to them.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import store
from reportal.store import now

# Environment variable naming the signature checkout to index.  Unset means no
# catalog: the routes report an empty one rather than guessing at a path.
SIGS_DIR_ENV = "REPORTAL_FLIRT_SIGS_DIR"

# The architecture index the rebrew-flirt-sigs checkout ships beside its
# ``.sig`` files.  Optional: without it a file is still indexed, with an empty
# arch and whatever its own name says.
INDEX_NAME = "index.json"

# Suffix the catalog accepts.  ``.pat`` is deliberately absent.
SIG_SUFFIX = ".sig"

# Architecture a file carries when neither the index nor its name says.
ARCH_UNKNOWN = ""

# Spellings the fingerprints and the signature checkout use for one ISA, folded
# onto the checkout's own spelling so a scan finds its signatures.  A value not
# in the table is kept as written rather than coerced.
_ARCH_ALIASES = {
    "x86_32": "x86",
    "i386": "x86",
    "i686": "x86",
    "x86": "x86",
    "x86_64": "x64",
    "amd64": "x64",
    "x64": "x64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "arm": "arm",
    "armhf": "arm",
    "mips": "mips",
    "mips64": "mips64",
    "ppc": "ppc",
    "powerpc": "ppc",
}

# How many compiled matchers one process keeps.  A matcher holds the whole
# signature library, so this is a memory bound, not a tuning knob: four covers
# the architectures a portal actually scans without holding every ISA at once.
MATCHER_CACHE_MAX = 4

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sigset (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rel_path       TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL DEFAULT '',
    arch           TEXT NOT NULL DEFAULT '',
    family         TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',
    blob_sha256    TEXT NOT NULL DEFAULT '',
    byte_size      INTEGER NOT NULL DEFAULT 0,
    pattern_count  INTEGER NOT NULL DEFAULT 0,
    enabled        INTEGER NOT NULL DEFAULT 1,
    indexed_at     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sigset_arch ON sigset(arch, enabled);

CREATE TABLE IF NOT EXISTS flirt_scan (
    binary_sha256 TEXT NOT NULL,
    sigset_key    TEXT NOT NULL,
    arch          TEXT NOT NULL DEFAULT '',
    match_count   INTEGER NOT NULL DEFAULT 0,
    matches_json  TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    PRIMARY KEY (binary_sha256, sigset_key, arch)
);
CREATE INDEX IF NOT EXISTS idx_flirt_scan_binary ON flirt_scan(binary_sha256);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the catalog and cache tables; safe on a database that has them."""
    conn.executescript(_SCHEMA)
    conn.commit()


def sigs_dir() -> Path | None:
    """The configured signature checkout, or None when the install has none."""
    raw = os.environ.get(SIGS_DIR_ENV, "").strip()
    return Path(raw) if raw else None


def sigs_dir_text() -> str:
    """The configured checkout as text for the settings report; "" when unset."""
    root = sigs_dir()
    return "" if root is None else str(root)


def normalize_arch(value: str | None) -> str:
    """Fold one ISA spelling onto the catalog's; unknown values pass through."""
    text = (value or "").strip().lower()
    return _ARCH_ALIASES.get(text, text)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_index(root: Path) -> dict[str, Any]:
    """The checkout's ``index.json`` as ``rel_path -> metadata``; empty if absent."""
    path = root / INDEX_NAME
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    files = payload.get("files") if isinstance(payload, dict) else None
    return files if isinstance(files, dict) else {}


def _arch_from_name(rel_path: str) -> str:
    """The architecture a filename carries, per the checkout's own naming."""
    stem = Path(rel_path).name.lower()
    for token, arch in (
        ("x86_64", "x64"),
        ("amd64", "x64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
        ("riscv64", "riscv64"),
        ("powerpc", "ppc"),
        ("i686", "x86"),
        ("x86", "x86"),
    ):
        if token in stem:
            return arch
    return ARCH_UNKNOWN


def refresh(conn: sqlite3.Connection, root: Path, *, prune: bool = False) -> dict[str, int]:
    """Index every ``.sig`` under *root* into the catalog.

    A file whose content hash is unchanged is left alone, so a re-run after a
    partial checkout is cheap and never bumps ``indexed_at`` needlessly.  A
    file that changed is updated in place, keeping its ``enabled`` flag: a
    consumer disabled a signature set, not a file version.  With *prune*, rows
    whose file is gone are deleted -- off by default, because a half-synced
    checkout should not read as a deleted library.
    """
    index = _load_index(root)
    added = updated = unchanged = 0
    seen: set[str] = set()
    for path in sorted(root.rglob(f"*{SIG_SUFFIX}")):
        if not path.is_file():
            continue
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(root.resolve()):
                continue
        except OSError:
            continue
        rel_path = path.relative_to(root).as_posix()
        if ".." in Path(rel_path).parts:
            continue
        seen.add(rel_path)
        meta = index.get(rel_path) or {}
        blob = _sha256_file(path)
        arch = normalize_arch(str(meta.get("arch") or "")) or _arch_from_name(rel_path)
        name = str(meta.get("name") or Path(rel_path).stem)
        row = conn.execute(
            "SELECT id, blob_sha256 FROM sigset WHERE rel_path = ?", (rel_path,)
        ).fetchone()
        if row is not None and str(row["blob_sha256"]) == blob:
            unchanged += 1
            continue
        fields = (
            name,
            arch,
            str(meta.get("family") or ""),
            str(meta.get("source") or ""),
            blob,
            path.stat().st_size,
            int(meta.get("patterns") or 0),
        )
        if row is None:
            conn.execute(
                "INSERT INTO sigset"
                " (rel_path, name, arch, family, source, blob_sha256, byte_size,"
                "  pattern_count, indexed_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rel_path, *fields, now()),
            )
            added += 1
        else:
            conn.execute(
                "UPDATE sigset SET name = ?, arch = ?, family = ?, source = ?,"
                " blob_sha256 = ?, byte_size = ?, pattern_count = ?, indexed_at = ?"
                " WHERE id = ?",
                (*fields, now(), row["id"]),
            )
            updated += 1
    pruned = 0
    if prune:
        for row in conn.execute("SELECT id, rel_path FROM sigset").fetchall():
            if str(row["rel_path"]) not in seen:
                conn.execute("DELETE FROM sigset WHERE id = ?", (row["id"],))
                pruned += 1
    conn.commit()
    if added or updated or pruned:
        # The live library moved; drop engines and scan rows keyed under the
        # previous digests so orphans cannot accumulate across refreshes.
        forget_matchers()
        prune_orphan_scans(conn)
    return {"added": added, "updated": updated, "unchanged": unchanged, "pruned": pruned}


def list_sigsets(
    conn: sqlite3.Connection, *, arch: str | None = None, enabled_only: bool = False
) -> list[dict[str, Any]]:
    """Catalog rows, newest first inside an architecture."""
    where: list[str] = []
    params: list[Any] = []
    if arch:
        where.append("arch = ?")
        params.append(normalize_arch(arch))
    if enabled_only:
        where.append("enabled = 1")
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(f"SELECT * FROM sigset{clause} ORDER BY arch, rel_path", params).fetchall()
    return [dict(row) for row in rows]


def set_enabled(conn: sqlite3.Connection, sigset_id: int, enabled: bool) -> bool:
    """Enable or disable one catalog row; False when the id is unknown.

    Toggling membership changes :func:`sigset_key`, so compiled matchers and
    orphaned ``flirt_scan`` rows keyed under the previous library are dropped.
    """
    cursor = conn.execute(
        "UPDATE sigset SET enabled = ? WHERE id = ?", (1 if enabled else 0, sigset_id)
    )
    conn.commit()
    if cursor.rowcount <= 0:
        return False
    forget_matchers()
    prune_orphan_scans(conn)
    return True


def sigset_key(conn: sqlite3.Connection, arch: str) -> str:
    """Digest of the enabled signature blobs one architecture would load.

    The empty string means "no signatures": a scan with no key is never
    cached, so an install that has not indexed anything cannot poison the cache
    with an empty result.
    """
    target = normalize_arch(arch)
    rows = conn.execute(
        "SELECT blob_sha256 FROM sigset"
        " WHERE enabled = 1 AND (arch = ? OR arch = ?) ORDER BY blob_sha256",
        (target, ARCH_UNKNOWN),
    ).fetchall()
    digests = [str(row["blob_sha256"]) for row in rows if row["blob_sha256"]]
    if not digests:
        return ""
    return hashlib.sha256("".join(digests).encode()).hexdigest()[:32]


def _blob_paths(conn: sqlite3.Connection, arch: str, root: Path) -> list[Path]:
    """The ``.sig`` files one architecture loads, unknown-arch files included.

    Each catalog ``rel_path`` is resolved under *root* and refused when it
    escapes (a ``..`` segment, an absolute path, or a symlink leaving the
    tree), so a poisoned catalog row cannot make the matcher read elsewhere.
    """
    target = normalize_arch(arch)
    rows = conn.execute(
        "SELECT rel_path FROM sigset WHERE enabled = 1 AND (arch = ? OR arch = ?)"
        " ORDER BY rel_path",
        (target, ARCH_UNKNOWN),
    ).fetchall()
    base = root.resolve()
    paths: list[Path] = []
    for row in rows:
        relative = str(row["rel_path"])
        if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
            continue
        candidate = (base / relative).resolve()
        if candidate == base or not candidate.is_relative_to(base):
            continue
        if candidate.is_file():
            paths.append(candidate)
    return paths


_MATCHERS: dict[tuple[str, str], Any] = {}
_MATCHERS_LOCK = threading.Lock()

# In-flight matcher builds keyed by ``(arch, sigset_key)``.  Compiling a
# signature library is the expensive half; holding ``_MATCHERS_LOCK`` across
# that work blocked every other architecture's hits.  The first miss builds,
# waiters park on the event and read the entry it installed.
_MATCHER_GATES: dict[tuple[str, str], threading.Event] = {}
_MATCHER_GATES_LOCK = threading.Lock()

# In-flight scan gates keyed by ``(binary_sha256, sigset_key, arch)``.  A miss
# under concurrency must not fan out into one full match per waiter: the first
# caller computes, the rest wait on the event and read the row it wrote.
_SCAN_GATES: dict[tuple[str, str, str], threading.Event] = {}
_SCAN_GATES_LOCK = threading.Lock()


def _build_matcher(blobs: Sequence[Path]) -> Any:
    """Compile the signature files into one matching engine.

    Imports ``flirt`` here rather than at module scope so an install without
    python-flirt still serves every other route.
    """
    try:
        import flirt
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise RuntimeError("python-flirt is not installed") from exc
    sigs: list[Any] = []
    for path in blobs:
        sigs.extend(flirt.parse_sig(path.read_bytes()))
    return flirt.compile(sigs)


def _touch_matcher(cache_key: tuple[str, str], matcher: Any) -> None:
    """Install *matcher* as the newest entry, evicting the oldest past the cap."""
    _MATCHERS.pop(cache_key, None)
    if len(_MATCHERS) >= MATCHER_CACHE_MAX:
        _MATCHERS.pop(next(iter(_MATCHERS)))
    _MATCHERS[cache_key] = matcher


def matcher_for(conn: sqlite3.Connection, arch: str, root: Path) -> tuple[str, Any | None]:
    """The cached engine for one architecture, with the key it was built under.

    Returns ``("", None)`` when the catalog holds no signatures for *arch*:
    the caller reports that rather than running an empty matcher.  Hits move
    the entry to the newest slot so eviction drops cold architectures first.
    Concurrent misses for the same key share one compile; the lock is not held
    across :func:`_build_matcher`, so a cold architecture cannot stall hits for
    a warm one.
    """
    key = sigset_key(conn, arch)
    if not key:
        return "", None
    cache_key = (normalize_arch(arch), key)
    with _MATCHERS_LOCK:
        cached = _MATCHERS.get(cache_key)
        if cached is not None:
            _touch_matcher(cache_key, cached)
            return key, cached
    with _MATCHER_GATES_LOCK:
        gate = _MATCHER_GATES.get(cache_key)
        leader = gate is None
        if leader:
            gate = threading.Event()
            _MATCHER_GATES[cache_key] = gate
    assert gate is not None
    if not leader:
        gate.wait()
        with _MATCHERS_LOCK:
            cached = _MATCHERS.get(cache_key)
            if cached is not None:
                _touch_matcher(cache_key, cached)
                return key, cached
        # Re-enter so a failed leader does not fan every waiter into its own
        # compile; one of them becomes the next leader under a fresh gate.
        return matcher_for(conn, arch, root)
    try:
        built = _build_matcher(_blob_paths(conn, arch, root))
        with _MATCHERS_LOCK:
            _touch_matcher(cache_key, built)
        return key, built
    finally:
        gate.set()
        with _MATCHER_GATES_LOCK:
            _MATCHER_GATES.pop(cache_key, None)


def _entries(matcher: Any, data: bytes) -> list[dict[str, str]]:
    """Match one buffer, flattened to one entry per reported name."""
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in matcher.match(data):
        for name in getattr(match, "names", ()):
            symbol = str(name[0]) if name else ""
            if not symbol:
                continue
            library = str(name[1]) if len(name) > 1 else ""
            pair = (symbol, library)
            if pair not in seen:
                seen.add(pair)
                entries.append({"name": symbol, "library": library})
    entries.sort(key=lambda entry: (entry["library"], entry["name"]))
    return entries


def cached_scan(conn: sqlite3.Connection, binary_sha256: str, arch: str) -> dict[str, Any] | None:
    """The stored matches for one (binary, signature library) pair."""
    key = sigset_key(conn, arch)
    if not key:
        return None
    row = conn.execute(
        "SELECT * FROM flirt_scan WHERE binary_sha256 = ? AND sigset_key = ? AND arch = ?",
        (binary_sha256, key, normalize_arch(arch)),
    ).fetchone()
    if row is None:
        return None
    return {
        "binary_sha256": str(row["binary_sha256"]),
        "arch": str(row["arch"]),
        "sigset_key": str(row["sigset_key"]),
        "match_count": int(row["match_count"]),
        "matches": json.loads(str(row["matches_json"])),
        "created_at": str(row["created_at"]),
        "cached": True,
    }


def _compute_scan(
    conn: sqlite3.Connection,
    *,
    binary_sha256: str,
    arch: str,
    data: bytes,
    root: Path,
) -> dict[str, Any]:
    """Run the matcher and upsert the row; callers own singleflight around this."""
    key, matcher = matcher_for(conn, arch, root)
    if matcher is None:
        return {
            "binary_sha256": binary_sha256,
            "arch": normalize_arch(arch),
            "sigset_key": "",
            "match_count": 0,
            "matches": [],
            "created_at": now(),
            "cached": False,
        }
    matches = _entries(matcher, data)
    target = normalize_arch(arch)
    created = now()
    conn.execute(
        "INSERT INTO flirt_scan"
        " (binary_sha256, sigset_key, arch, match_count, matches_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(binary_sha256, sigset_key, arch) DO UPDATE SET"
        " match_count = excluded.match_count, matches_json = excluded.matches_json,"
        " created_at = excluded.created_at",
        (binary_sha256, key, target, len(matches), json.dumps(matches), created),
    )
    conn.commit()
    return {
        "binary_sha256": binary_sha256,
        "arch": target,
        "sigset_key": key,
        "match_count": len(matches),
        "matches": matches,
        "created_at": created,
        "cached": False,
    }


def scan(
    conn: sqlite3.Connection,
    *,
    binary_sha256: str,
    arch: str,
    data: bytes,
    root: Path,
) -> dict[str, Any]:
    """Match *data* against the enabled signatures, or return the cached result.

    The write is an upsert on ``(binary_sha256, sigset_key, arch)``.  A catalog
    change moves the key and :func:`prune_orphan_scans` drops the previous row,
    so a miss under the new library is a fresh match.  Concurrent misses for
    the same key share one compute: waiters read the row the leader wrote.
    """
    hit = cached_scan(conn, binary_sha256, arch)
    if hit is not None:
        return hit
    key = sigset_key(conn, arch)
    if not key:
        return _compute_scan(conn, binary_sha256=binary_sha256, arch=arch, data=data, root=root)
    gate_key = (binary_sha256, key, normalize_arch(arch))
    with _SCAN_GATES_LOCK:
        gate = _SCAN_GATES.get(gate_key)
        leader = gate is None
        if leader:
            gate = threading.Event()
            _SCAN_GATES[gate_key] = gate
    assert gate is not None
    if not leader:
        gate.wait()
        hit = cached_scan(conn, binary_sha256, arch)
        if hit is not None:
            return hit
        # Re-enter so a failed leader does not fan every waiter into its own
        # match; one of them becomes the next leader under a fresh gate.
        return scan(conn, binary_sha256=binary_sha256, arch=arch, data=data, root=root)
    try:
        return _compute_scan(conn, binary_sha256=binary_sha256, arch=arch, data=data, root=root)
    finally:
        # Wake waiters before dropping the gate so a late arriver cannot start a
        # second compute while the first cohort is still parked on this event.
        gate.set()
        with _SCAN_GATES_LOCK:
            _SCAN_GATES.pop(gate_key, None)


def prune_orphan_scans(conn: sqlite3.Connection) -> int:
    """Drop ``flirt_scan`` rows whose ``sigset_key`` is no longer the live library.

    Cached reads only look up the current key, so an orphan is never served;
    pruning keeps the table from growing one dead row per catalog revision.
    """
    live: dict[str, str] = {}
    deleted = 0
    for row in conn.execute("SELECT DISTINCT arch FROM flirt_scan").fetchall():
        arch = str(row["arch"])
        live[arch] = sigset_key(conn, arch)
    for arch, key in live.items():
        if key:
            cursor = conn.execute(
                "DELETE FROM flirt_scan WHERE arch = ? AND sigset_key != ?", (arch, key)
            )
        else:
            cursor = conn.execute("DELETE FROM flirt_scan WHERE arch = ?", (arch,))
        deleted += int(cursor.rowcount)
    if deleted:
        conn.commit()
    return deleted


def clear_cache(conn: sqlite3.Connection) -> int:
    """Drop every cached scan; the catalog is untouched.

    The upgrade path after a signature refresh that kept the same key, and the
    hammer for a matcher bug: results are derived data, so dropping them costs
    one re-scan per binary and nothing else.
    """
    cursor = conn.execute("DELETE FROM flirt_scan")
    conn.commit()
    return cursor.rowcount


def forget_matchers() -> None:
    """Drop the in-process engines; the next scan rebuilds from the catalog.

    In-flight build gates are woken and dropped too, so waiters do not sit on
    an event whose leader's result was discarded by a catalog refresh.
    """
    with _MATCHERS_LOCK:
        _MATCHERS.clear()
    with _MATCHER_GATES_LOCK:
        pending = list(_MATCHER_GATES.values())
        _MATCHER_GATES.clear()
    for gate in pending:
        gate.set()


# ── The stored reading ─────────────────────────────────────────────
#
# A scan is the portal-visible reading; ``flirt_scan`` above is only the cache
# that keeps the same bytes from being matched twice.  Storing both is
# deliberate: every other capability's reading lives in ``scans``, so the scans
# listing, the CLI, the MCP tools and the journal all see this one the same way.

# Source recorded on a rename this module applies; also the actor.
PROPOSAL_SOURCE = "flirt"

# The one name source a proposal refuses to overwrite: a person typed it.
MANUAL_SOURCE = "manual"

# How many matches a stored reading keeps.  A linked MSVC runtime can match
# thousands of symbols; the payload is a reading, not a dump, and the cache
# above is where the whole list stays.
MAX_STORED_MATCHES = 500


class FlirtError(Exception):
    """A FLIRT run that could not happen, with the code the API answers."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class ManualNameError(Exception):
    """A proposal refused to overwrite a name a person authored."""


def _binary_path(conn: sqlite3.Connection, binary_id: int) -> Path:
    """The binary's file on disk, refusing one that is not there."""
    row = store.get_binary(conn, binary_id)
    if row is None:
        raise KeyError(f"no binary with id {binary_id}")
    path = Path(str(row["path"] or ""))
    if not path.is_file():
        raise FlirtError("binary not on disk", f"binary {binary_id} has no readable file")
    return path


def _arch_for(conn: sqlite3.Connection, binary_id: int, requested: str) -> str:
    """The caller's architecture, else the stored fingerprint's, else unknown."""
    if requested.strip():
        return normalize_arch(requested)
    stored = store.get_fingerprint(conn, binary_id) or {}
    return normalize_arch(str(stored.get("arch") or ""))


def rollup(matches: Sequence[Mapping[str, str]]) -> list[dict[str, Any]]:
    """Group matched symbols by the library they came from, biggest first.

    The count is symbols matched in the buffer, not functions the binary
    contains: the matcher reports names, and a name is not an address, so the
    reading never claims a function it did not locate.
    """
    grouped: dict[str, list[str]] = {}
    for match in matches:
        library = str(match.get("library") or "").strip() or "unknown"
        grouped.setdefault(library, []).append(str(match.get("name") or ""))
    found: list[dict[str, Any]] = [
        {"library": library, "matches": len(names), "names": sorted(set(names))}
        for library, names in grouped.items()
    ]
    found.sort(key=lambda entry: (-int(entry["matches"]), str(entry["library"])))
    return found


def run_flirt(conn: sqlite3.Connection, *, binary_id: int, arch: str = "") -> dict[str, Any]:
    """Match a binary against the enabled signatures and store the reading.

    The bytes come from the binary's own file, the architecture from the
    caller or its fingerprint, and the result from the scan cache when these
    bytes were already matched under this signature library.  Nothing is
    renamed.
    """
    root = sigs_dir()
    if root is None or not root.is_dir():
        raise FlirtError("no-signature-dir", f"set {SIGS_DIR_ENV} to a signature checkout")
    path = _binary_path(conn, binary_id)
    target = _arch_for(conn, binary_id, arch)
    data = path.read_bytes()
    result = scan(
        conn,
        binary_sha256=hashlib.sha256(data).hexdigest(),
        arch=target,
        data=data,
        root=root,
    )
    matches = list(result["matches"])
    modules = rollup(matches)
    notes = [
        (
            "matches come from the compiled signatures themselves; a library no"
            " signature set covers is absent rather than guessed at"
        )
    ]
    if not result["sigset_key"]:
        notes.append("no signature set covers this architecture, so nothing was matched")
    if result["cached"]:
        notes.append("served from the cached scan of these same bytes")
    if len(matches) > MAX_STORED_MATCHES:
        notes.append(f"the reading keeps the first {MAX_STORED_MATCHES} matches")
    payload = {
        "binary_id": binary_id,
        "stored": True,
        "arch": target,
        "sigset_key": result["sigset_key"],
        "match_count": len(matches),
        "matches": matches[:MAX_STORED_MATCHES],
        "libraries": modules,
        "modules": len(modules),
        "cached": bool(result["cached"]),
        "notes": notes,
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_FLIRT, payload, params={"arch": target})
    return payload


def stored_reading(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The stored signature reading of one binary, or None before the first run."""
    from reportal import details

    return details.stored_scan(conn, binary_id, store.SCAN_KIND_FLIRT)


def apply_proposal(conn: sqlite3.Connection, *, function_id: int, new_name: str) -> dict[str, Any]:
    """Rename *function_id* to one of the matched library symbols.

    A refused function is the one a person already named: a signature match is
    evidence, and evidence does not overwrite an authored name.  Everything
    else is renamed with source ``flirt``, so the change is attributed and
    revertible through ``name_history``.
    """
    if not new_name.strip():
        raise ValueError("name must not be empty")
    function = store.get_function(conn, function_id)
    if function is None:
        raise KeyError(f"no function with id {function_id}")
    if str(function.get("name_source") or "") == MANUAL_SOURCE:
        raise ManualNameError(f"function {function_id} carries a name a person authored")
    return store.rename_function(
        conn,
        function_id,
        new_name=new_name,
        actor=PROPOSAL_SOURCE,
        source=PROPOSAL_SOURCE,
    )

"""A workspace library of debug symbol files, matched to binaries by identity.

The per-binary ingest in :mod:`reportal.symbols` answers "here is the symbol
file for *this* binary" after someone already holds the file.  A library
answers earlier: reportal stores the PDBs and ELF debug files of common system
and vendor libraries once (libcmt, DirectX, and any other build the operator
collects), keys each entry by the identity its binary carries, and applies an
entry to any stored binary whose identity matches.

Two identities are read here by stdlib byte parsers that take the bytes of one
file and write nothing:

* a PE image's debug directory (:func:`pe_debug_id`): the CodeView record the
  linker emitted carries the GUID and the age of its PDB and the PDB's path,
  and :func:`reportal.pdb.read_identity` reads the same pair from the PDB
  itself, so ``pe:<guid>-<age>`` is exact: that PDB is the one built for that
  image.  Both sides store the same 16 bytes, so the match compares bytes, not
  a rendering of them;
* an ELF's GNU build id (:func:`reportal.symbols.build_id`): the ``elf:<hex>``
  note the linker stamped into the binary and, when the debug file was split
  off, into the file kept beside it.

Matching is one indexed lookup (:func:`find`), and applying a match is
:func:`reportal.symbols.import_symbols` inside one journaled action, so a
library resolve reverts like every other write.  Nothing here executes a
sample and the parsers are the same bounded readers ``symbols.py`` and
``pdb.py`` already run over untrusted bytes.

When no stored entry carries a PE identity, :func:`resolve` may ask the
Microsoft public symbol server for the PDB (:func:`fetch_pdb`).  That is the
network, so it obeys the external-source gate: remote sources must be enabled
(``REPORTAL_ALLOW_EXTERNAL`` or ``[external] allow_remote = true``), an
explicit fetch while they are off is the same 403 ``external-disabled``, and
while they are off no request leaves the process.  The scheme, host and path
shape are fixed; only a validated file name from the image's own debug record
and the binary's own identity become path components, redirects are not
followed and the body is bounded.  The automatic resolves that run after an
upload or an ``import-rebrew`` never fetch: they only read the local library.
"""

from __future__ import annotations

import json
import logging
import mmap
import re
import sqlite3
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx2 as httpx

from reportal import external, journal, pdb, store, symbols
from reportal.symbols import Buffer

_log = logging.getLogger(__name__)

# The table the library entries live in (created on first use), and the two
# identity prefixes its rows are keyed by.
TABLE = "symbol_library"
IDENTITY_PE = "pe"
IDENTITY_ELF = "elf"

# The error code a file that parses but can never match answers.
ERROR_NO_IDENTITY = "no-identity"

# The one public symbol server this build fetches from.  The host and scheme
# are fixed so a caller cannot aim the request elsewhere; the path is built
# from the image's own debug record.
SYMBOL_SERVER_HOST = "msdl.microsoft.com"
SYMBOL_SERVER_BASE = f"https://{SYMBOL_SERVER_HOST}/download/symbols"

# A PDB file name as it may appear in a URL path: a plain name, no separator,
# no traversal, no query.  Anything else (a full link path with directories, a
# name another server would answer) skips the fetch instead of being rewritten.
_SERVER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.pdb", re.IGNORECASE)

# Request bounds: the body is capped at the size an upload gets and the call
# gets a wall-clock limit.  A symbol server redirect is a refusal, not a hop.
MAX_FETCH_BYTES = 256 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 60.0
USER_AGENT = "reportal symbol-library"

# PE bounds: the number of sections a debug directory is read through, the
# byte size of one IMAGE_DEBUG_DIRECTORY entry, its CodeView type value and
# the CodeView record's magic ("RSDS" carries the GUID, the age and the path;
# the older "NB" records carry no GUID and are skipped).
_MAX_SECTIONS = 96
_DEBUG_ENTRY_SIZE = 28
_DEBUG_TYPE_CODEVIEW = 2
_RSDS = b"RSDS"
_HEADER_SIZE = 0x40


class SymbolLibraryError(Exception):
    """A rejected library operation; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class NoIdentityError(SymbolLibraryError, ValueError):
    """The file parses but carries no match key; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NO_IDENTITY, detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the library table when the database predates it."""
    conn.executescript(_SCHEMA)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS symbol_library (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    origin      TEXT NOT NULL DEFAULT '',
    identity    TEXT NOT NULL DEFAULT '',
    pdb_name    TEXT NOT NULL DEFAULT '',
    parsed_json TEXT NOT NULL DEFAULT '{}',
    symbols     INTEGER NOT NULL DEFAULT 0,
    types       INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_symbol_library_identity ON symbol_library(identity);
"""


# ── Identity readers ───────────────────────────────────────────────


def pe_debug_id(data: Buffer) -> dict[str, Any] | None:
    """The CodeView debug record of a PE image, or None when it carries none.

    Returns ``{"guid", "age", "pdb_name"}``: the GUID as the lowercase hex of
    the 16 record bytes, the age as an int and the PDB name the linker stored
    (its last path component, since the original is a build-machine path).
    Every bound is checked, so a malformed image answers None instead of a
    partial answer: this value becomes a match key and a fetch path.
    """
    if len(data) < _HEADER_SIZE or bytes(data[:2]) != b"MZ":
        return None
    try:
        pe_at = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_at + 24 > len(data) or bytes(data[pe_at : pe_at + 4]) != b"PE\0\0":
            return None
        coff = pe_at + 4
        section_count = int(struct.unpack_from("<H", data, coff + 2)[0])
        size_optional = int(struct.unpack_from("<H", data, coff + 16)[0])
        optional = coff + 20
        if size_optional < 2 or optional + size_optional > len(data):
            return None
        magic = int(struct.unpack_from("<H", data, optional)[0])
        if magic == 0x10B:  # PE32
            rva_count_at, data_directory_at = 92, 96
        elif magic == 0x20B:  # PE32+
            rva_count_at, data_directory_at = 108, 112
        else:
            return None
        if size_optional >= rva_count_at + 4:
            rva_count = int(struct.unpack_from("<I", data, optional + rva_count_at)[0])
            if rva_count <= 6:
                return None
        if size_optional < data_directory_at + 7 * 8:
            return None
        debug_rva, debug_size = struct.unpack_from(
            "<II", data, optional + data_directory_at + 6 * 8
        )
        if not debug_rva or debug_size < _DEBUG_ENTRY_SIZE:
            return None
        sections = _pe_sections(data, optional + size_optional, section_count)
        if sections is None:
            return None
        debug_at = _rva_to_raw(data, sections, int(debug_rva))
        if debug_at is None:
            return None
        for index in range(int(debug_size) // _DEBUG_ENTRY_SIZE):
            entry = debug_at + index * _DEBUG_ENTRY_SIZE
            if entry + _DEBUG_ENTRY_SIZE > len(data):
                return None
            entry_type = int(struct.unpack_from("<I", data, entry + 12)[0])
            if entry_type != _DEBUG_TYPE_CODEVIEW:
                continue
            record = _codeview_record(data, sections, entry)
            if record is not None:
                return record
    except struct.error:
        return None
    return None


def _pe_sections(data: Buffer, offset: int, count: int) -> list[tuple[int, int, int, int]] | None:
    """The section table as ``(virtual_address, virtual_size, raw_size, raw_offset)``."""
    if count <= 0 or count > _MAX_SECTIONS:
        return None
    sections: list[tuple[int, int, int, int]] = []
    for index in range(count):
        at = offset + index * 40
        if at + 40 > len(data):
            return None
        _name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<8sIIII", data, at
        )
        sections.append((int(virtual_address), int(virtual_size), int(raw_size), int(raw_offset)))
    return sections


def _rva_to_raw(data: Buffer, sections: list[tuple[int, int, int, int]], rva: int) -> int | None:
    """The file offset of *rva*, or None when no section holds it."""
    for virtual_address, virtual_size, raw_size, raw_offset in sections:
        span = max(virtual_size, raw_size)
        if span and virtual_address <= rva < virtual_address + span:
            raw = raw_offset + (rva - virtual_address)
            return raw if 0 <= raw < len(data) else None
    return None


def _codeview_record(
    data: Buffer, sections: list[tuple[int, int, int, int]], entry: int
) -> dict[str, Any] | None:
    """The RSDS record one debug-directory entry points at, or None."""
    data_size = int(struct.unpack_from("<I", data, entry + 16)[0])
    address_rva = int(struct.unpack_from("<I", data, entry + 20)[0])
    pointer = int(struct.unpack_from("<I", data, entry + 24)[0])
    if pointer and pointer + data_size <= len(data):
        record_at = pointer
    else:
        converted = _rva_to_raw(data, sections, address_rva)
        if converted is None or converted + data_size > len(data):
            return None
        record_at = converted
    record = bytes(data[record_at : record_at + data_size])
    if len(record) < 24 or record[:4] != _RSDS:
        return None
    guid = record[4:20].hex()
    age = int(struct.unpack_from("<I", record, 20)[0])
    raw_name = record[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {"guid": guid, "age": age, "pdb_name": raw_name.replace("\\", "/").rsplit("/", 1)[-1]}


def binary_identity(path: Path) -> tuple[str, str, str]:
    """``(identity, pdb_name, reason)`` for one stored binary's own bytes.

    The file is mapped rather than read whole, so a 256 MiB upload costs one
    page-touched walk of its headers.  ``identity`` is empty when it cannot be
    read, and ``reason`` then says why in words an operator can act on.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        return "", "", f"the binary file cannot be read: {exc}"
    if size == 0:
        return "", "", "the binary file is empty"
    try:
        with (
            path.open("rb") as handle,
            mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as blob,
        ):
            head = bytes(blob[:4])
            if head[:2] == b"MZ":
                debug = pe_debug_id(blob)
                if debug is None:
                    return "", "", "the image's debug directory carries no CodeView record"
                identity = f"{IDENTITY_PE}:{debug['guid']}-{int(debug['age'])}"
                return identity, str(debug["pdb_name"]), ""
            if head == symbols.ELF_MAGIC[:4]:
                found = symbols.build_id(blob)
                if not found:
                    return "", "", "the ELF carries no GNU build id to match a debug file on"
                return f"{IDENTITY_ELF}:{found}", "", ""
            return "", "", "the file is neither a PE image nor an ELF file"
    except (OSError, ValueError) as exc:
        return "", "", f"the binary file cannot be mapped: {exc}"


def file_identity(data: bytes) -> str:
    """The identity a symbol file's own bytes carry.

    ``pe:<guid>-<age>`` for a PDB and ``elf:<hex>`` for an ELF with a GNU build
    id.  Raises :class:`symbols.UnreadableSymbolError` for a file this reader
    cannot follow and :class:`NoIdentityError` for one that parses but carries
    no key: an entry no binary could ever match is refused rather than stored
    as dead weight.
    """
    if data[: len(symbols.PDB_MAGIC)] == symbols.PDB_MAGIC:
        try:
            parsed = pdb.read_identity(data)
        except pdb.PdbError as exc:
            raise NoIdentityError(exc.detail) from exc
        return f"{IDENTITY_PE}:{parsed['guid']}-{int(parsed['age'])}"
    if data[:4] == symbols.ELF_MAGIC:
        found = symbols.build_id(data)
        if not found:
            raise NoIdentityError("the ELF carries no GNU build id to match a binary on")
        return f"{IDENTITY_ELF}:{found}"
    raise symbols.UnreadableSymbolError("the file is not an ELF or a PDB container")


# ── The store ──────────────────────────────────────────────────────


def _row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """One stored library entry as the surfaces report it (no whole parse)."""
    return {
        "id": int(row["id"]),
        "sha256": str(row["sha256"]),
        "kind": str(row["kind"]),
        "size": int(row["size"]),
        "origin": str(row["origin"]),
        "identity": str(row["identity"]),
        "pdb_name": str(row["pdb_name"]),
        "symbols": int(row["symbols"]),
        "types": int(row["types"]),
        "created_at": str(row["created_at"]),
    }


def list_entries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every library entry, newest first, without the stored parses."""
    ensure_schema(conn)
    rows = conn.execute(f"SELECT * FROM {TABLE} ORDER BY id DESC").fetchall()
    return [_row(row) for row in rows]


def find(conn: sqlite3.Connection, identity: str) -> dict[str, Any] | None:
    """The newest entry carrying *identity* with its parse, or None."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE identity = ? ORDER BY id DESC LIMIT 1", (str(identity),)
    ).fetchone()
    if row is None:
        return None
    return {**_row(row), "parsed": json.loads(str(row["parsed_json"]) or "{}")}


def add(
    conn: sqlite3.Connection, log: journal.Journal, data: bytes, *, origin: str = ""
) -> dict[str, Any]:
    """Parse one symbol file, key it by its identity and store it.

    The bytes land content-addressed under the workspace's ``symbols/``
    directory beside every per-binary ingest, the parse is stored with the row
    so a resolve never re-parses a vendor PDB, and the row is journaled so a
    revert takes it back.  The same bytes twice answer the existing row with
    ``duplicate: true`` and write nothing.
    """
    parsed = symbols.parse(data, filename=origin or "the file")
    return store_entry(conn, log, data, parsed=parsed, identity=file_identity(data), origin=origin)


def store_entry(
    conn: sqlite3.Connection,
    log: journal.Journal,
    data: bytes,
    *,
    parsed: Mapping[str, Any],
    identity: str,
    origin: str = "",
) -> dict[str, Any]:
    """Store an already parsed and identified symbol file; see :func:`add`.

    The batch surfaces parse and identify every file before the first write,
    so one refused file cannot leave a half-added batch behind; this half
    writes without re-reading what they already established.
    """
    ensure_schema(conn)
    sha256 = symbols.digest(data)
    existing = conn.execute(f"SELECT * FROM {TABLE} WHERE sha256 = ?", (sha256,)).fetchone()
    if existing is not None:
        return {**_row(existing), "duplicate": True}
    symbols.persist_bytes(data)
    name = origin.replace("\\", "/").rsplit("/", 1)[-1] if origin else ""
    cursor = conn.execute(
        f"INSERT INTO {TABLE} (sha256, kind, size, origin, identity, pdb_name, parsed_json,"
        " symbols, types, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sha256,
            str(parsed.get("kind") or ""),
            len(data),
            origin,
            identity,
            name if identity.startswith(IDENTITY_PE + ":") else "",
            json.dumps(dict(parsed), sort_keys=True),
            len(parsed.get("symbols") or []),
            len(parsed.get("types") or []),
            store.now(),
        ),
    )
    conn.commit()
    entry_id = int(cursor.lastrowid or 0)
    journal.journaled_create(
        log,
        table=TABLE,
        key=entry_id,
        description=f"added a {parsed.get('kind')} symbol file to the library ({identity})",
    )
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (entry_id,)).fetchone()
    if row is None:  # the INSERT just committed; only a concurrent delete gets here
        raise SymbolLibraryError("write-failed", "the stored library row vanished")
    return {**_row(row), "duplicate": False}


# ── The symbol server fetch ────────────────────────────────────────


def symbol_server_url(name: str, guid: str, age: int) -> str:
    """The URL one PDB is served under.

    The store layout is ``<name>/<id>/<name>`` where the id is the GUID as
    uppercase hex without separators, with the age in decimal appended (the
    age is a single digit in every modern link, where the two candidate bases
    agree).  Only a name that passed :data:`_SERVER_NAME` reaches this.
    """
    return f"{SYMBOL_SERVER_BASE}/{name}/{guid.upper()}{age}/{name}"


def fetch_pdb(name: str, guid: str, age: int) -> bytes | None:
    """The PDB the public symbol server holds for one identity, or None.

    A miss (404) is None, not an error: it is the answer "this identity is not
    served".  Remote sources must be enabled or this raises the same
    ``external-disabled`` refusal before a socket is opened; a redirect, a
    non-200 answer or a body past :data:`MAX_FETCH_BYTES` raises the external
    source's own failure codes.  A name that is not a plain ``.pdb`` file name
    raises :class:`SymbolLibraryError` and is never sent.
    """
    external.require_enabled()
    if not _SERVER_NAME.fullmatch(name):
        raise SymbolLibraryError(
            ERROR_NO_IDENTITY, f"{name!r} is not a plain .pdb file name to fetch"
        )
    url = symbol_server_url(name, guid, age)
    client, owned = external._open_client(FETCH_TIMEOUT_SECONDS)
    try:
        with client.stream(
            "GET",
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"},
        ) as response:
            if response.status_code == 404:
                return None
            if response.is_redirect:
                raise external.ExternalFetchError(
                    f"the symbol server answered a redirect ({response.status_code});"
                    " it is not followed",
                    external.ERROR_BAD_RESPONSE,
                )
            if response.status_code != 200:
                raise external.ExternalFetchError(
                    f"the symbol server answered {response.status_code}",
                    external.ERROR_FETCH_FAILED,
                )
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_FETCH_BYTES:
                raise external.ExternalFetchError(
                    f"the response is larger than {MAX_FETCH_BYTES} bytes",
                    external.ERROR_TOO_LARGE,
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_FETCH_BYTES:
                    raise external.ExternalFetchError(
                        f"the response is larger than {MAX_FETCH_BYTES} bytes",
                        external.ERROR_TOO_LARGE,
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except external.ExternalError:
        raise
    except httpx.HTTPError as exc:
        raise external.ExternalFetchError(f"the symbol server request failed: {exc}") from exc
    finally:
        if owned:
            client.close()


# ── The resolve ────────────────────────────────────────────────────


def _unmatched(report: dict[str, Any], reason: str, fetch: str) -> dict[str, Any]:
    """The standard unmatched answer: what was not found, why, fetch state."""
    report.update({"matched": False, "source": None, "reason": reason, "fetch": fetch})
    return report


def resolve(
    conn: sqlite3.Connection, binary_id: int, *, fetch: bool | None = None
) -> dict[str, Any]:
    """Match a binary to a library entry and apply it as one journaled action.

    ``fetch`` is tri-state: None (the default) fetches a missing PDB only when
    the operator already enabled remote sources, True forces the fetch (and
    answers the external gate's 403 ``external-disabled`` when they are off),
    and False never touches the network.  When nothing matches, the report
    says which identity was looked for and why it found nothing, and nothing
    is journaled.  When something matches, the entry's stored parse is applied
    through :func:`reportal.symbols.import_symbols` (functions renamed with
    the ``symbol`` name source, aggregate types added), a fetch first stores
    its answer in the library inside the same action, and the returned report
    carries the ingest under ``ingest``.
    """
    ensure_schema(conn)
    binary = store.get_binary(conn, int(binary_id))
    if binary is None:
        raise SymbolLibraryError("binary not found", f"no binary with id {binary_id}")
    report: dict[str, Any] = {
        "binary_id": int(binary_id),
        "identity": "",
        "matched": False,
        "source": None,
        "reason": "",
        "fetch": "not-attempted",
    }
    identity, pdb_name, reason = binary_identity(Path(str(binary["path"] or "")))
    report["identity"] = identity
    if not identity:
        return _unmatched(report, reason, "not-attempted")

    entry = find(conn, identity)
    origin = ""
    source = "library"
    fetch_state = "not-needed"
    if entry is not None:
        stored = symbols.stored_path(str(entry["sha256"]))
        try:
            data = stored.read_bytes()
        except OSError:
            return _unmatched(
                report,
                f"the library holds {identity} but its stored file is missing on disk",
                "not-needed",
            )
        parsed: dict[str, Any] = dict(entry.get("parsed") or {})
        entry_id = int(entry["id"])
    else:
        wanted = external.remote_enabled() if fetch is None else fetch
        if not identity.startswith(IDENTITY_PE + ":"):
            tail = "; the public symbol server serves PDB identities only" if wanted else ""
            return _unmatched(
                report, f"no library entry carries {identity}{tail}", "not-applicable"
            )
        if not wanted:
            auto_off = fetch is None and not external.remote_enabled()
            fetch_state = "disabled" if auto_off else "skipped"
            detail = f"no library entry carries {identity}"
            if fetch_state == "disabled":
                detail += " and remote sources are off, so the symbol server was not asked"
            return _unmatched(report, detail, fetch_state)
        if not external.remote_enabled():
            raise external.DisabledExternalError
        fetch_state = "attempted"
        guid, _, age_text = identity.removeprefix(IDENTITY_PE + ":").partition("-")
        try:
            served = fetch_pdb(pdb_name, guid, int(age_text))
        except SymbolLibraryError as exc:
            return _unmatched(
                report,
                f"no library entry carries {identity} and it was not fetched: {exc.detail}",
                "refused",
            )
        if served is None:
            return _unmatched(
                report,
                f"no library entry carries {identity} and the symbol server does not serve it",
                "miss",
            )
        try:
            fetched_identity = file_identity(served)
            parsed = symbols.parse(served, filename=pdb_name)
        except (symbols.UnreadableSymbolError, NoIdentityError) as exc:
            raise external.ExternalFetchError(
                f"the symbol server's answer is not a symbol file: {exc}",
                external.ERROR_BAD_RESPONSE,
            ) from exc
        if fetched_identity != identity:
            return _unmatched(
                report,
                f"the symbol server answered with {fetched_identity}, not {identity}",
                "mismatch",
            )
        data = served
        origin = symbol_server_url(pdb_name, guid, int(age_text))
        source = "symbol-server"

    with journal.journaled(conn, journal.new_action()) as log:
        if source == "symbol-server":
            stored_row = add(conn, log, data, origin=origin)
            entry_id = int(stored_row["id"])
            fetch_state = "stored"
        ingest = symbols.import_symbols(
            conn,
            log,
            binary_id=int(binary_id),
            data=data,
            parsed=parsed,
            path=str(symbols.stored_path(symbols.digest(data))),
            apply=True,
        )
        report = dict(log.attach(report))
    report.update(
        {
            "matched": True,
            "source": source,
            "reason": "",
            "fetch": fetch_state,
            "entry_id": entry_id,
            "ingest": ingest,
        }
    )
    return report


def auto_resolve(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The local-only resolve an upload or an import runs: never a network call.

    Best effort and never raises, so a symbol lookup can fail (a missing file,
    an unreadable header) without failing the operation that triggered it; the
    reason lands in the returned report instead.
    """
    try:
        return resolve(conn, int(binary_id), fetch=False)
    except Exception as exc:  # a hook must not take down the write that called it
        _log.warning("symbol resolve failed for binary %s: %s", binary_id, exc)
        return {
            "binary_id": int(binary_id),
            "identity": "",
            "matched": False,
            "source": None,
            "reason": f"symbol resolve failed: {exc}",
            "fetch": "not-attempted",
        }

"""SQLite schema and typed CRUD for the reportal portal.

The database is reportal's only persistent state: binaries, analyses,
functions, cross-function matches, rename history, collections, tags,
malware-family signatures, scans, engine fingerprints, rebrew project
contexts, stored decompilations, AI artifacts, analyst comments, conversations
with their message history, the pipeline runs of the AI decompilation
composition with their steps, the auto-mode runs with their task tree and
per-attempt log, the knowledge documents with their chunks, the knowledge graph
nodes and edges, and the editable data types with their function signatures and
signature history.  Readers return plain ``dict`` rows so the JSON API
serializes them without a mapping layer; writers commit on their own.

``functions`` carries a ``UNIQUE (analysis_id, va)`` constraint so
``upsert_function`` makes re-imports idempotent: a function is identified by
its VA inside one analysis, and a second import refreshes it in place.

``analyses.status`` is the source of truth for where an analysis stands; the
lifecycle writers here advance it and record what happened in the structured
log (:mod:`reportal.analysis_log`), so an analysis whose scan failed is
``failed`` rather than silently complete.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sqlite3
import threading
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from reportal import analysis_log, auth, metering
from reportal import clock as _clock
from reportal._paths import db_path as workspace_db_path

_log = logging.getLogger(__name__)


def now() -> str:
    """Return the current UTC time as an ISO 8601 string (second resolution).

    Delegates to :func:`reportal.clock.now`.  Patch ``reportal.clock.now`` to
    pin timestamps; ``store.now``, ``auth.now``, ``journal.now`` and
    ``analysis_log.now`` all read that one function.
    """
    return _clock.now()


def as_utc(value: str) -> datetime:
    """Parse an ISO stamp as an aware UTC datetime; see :func:`reportal.clock.as_utc`."""
    return _clock.as_utc(value)


def as_utc_iso(value: str) -> str:
    """Normalize *value* to UTC ``+00:00`` form; see :func:`reportal.clock.as_utc_iso`."""
    return _clock.as_utc_iso(value)


# Function statuses that count as a byte-equality match.  Mirrors rebrew's
# MATCHED_STATUSES so `reportal stats` reports the same number recoverage does.
MATCHED_STATUSES = frozenset({"EXACT", "RELOC", "PROVEN", "MATCHED"})

# Analysis statuses, the one place the set is defined.  They map onto the
# hosted portal's lifecycle: `pending` is its Queued, `processing` its
# Processing, `done` its Complete and `failed` its Error; `cancelled` is
# reportal's own.  `create_analysis` and `update_analysis_status` refuse a
# value outside the set rather than storing it.
ANALYSIS_STATUS_PENDING = "pending"
ANALYSIS_STATUS_PROCESSING = "processing"
ANALYSIS_STATUS_DONE = "done"
ANALYSIS_STATUS_FAILED = "failed"
ANALYSIS_STATUS_CANCELLED = "cancelled"
ANALYSIS_STATUSES: tuple[str, ...] = (
    ANALYSIS_STATUS_PENDING,
    ANALYSIS_STATUS_PROCESSING,
    ANALYSIS_STATUS_DONE,
    ANALYSIS_STATUS_FAILED,
    ANALYSIS_STATUS_CANCELLED,
)

# Analysis statuses that close an analysis; update_analysis_status stamps
# finished_at on these without the caller passing a timestamp.
TERMINAL_STATUSES = frozenset(
    {ANALYSIS_STATUS_DONE, ANALYSIS_STATUS_FAILED, ANALYSIS_STATUS_CANCELLED}
)

# Scan kinds stored in the `scans` table, one row per (analysis, kind).
SCAN_KIND_TRIAGE = "triage"
SCAN_KIND_REPORT = "report"
SCAN_KIND_STRUCTS = "structs"
SCAN_KIND_CRYPTO = "crypto"
SCAN_KIND_SECURITY = "security"
SCAN_KIND_UNSTRIP = "unstrip"
SCAN_KIND_CAPABILITIES = "capabilities"
SCAN_KIND_THREAT = "threat"
SCAN_KIND_REMEDIATION = "remediation"
SCAN_KIND_EXECUTION = "execution"
SCAN_KIND_NETWORKING = "networking"
SCAN_KIND_FILESYSTEM = "filesystem"
SCAN_KIND_SECRETS = "secrets"
SCAN_KIND_ANTI_ANALYSIS = "anti-analysis"
SCAN_KIND_OBFUSCATION = "obfuscation"
SCAN_KIND_LINEAGE = "lineage"
SCAN_KIND_DETECT = "detect"
SCAN_KIND_PROTOCOLS = "protocols"
SCAN_KIND_FUNCTION_TRIAGE = "function-triage"
SCAN_KIND_RELATED = "related"
SCAN_KIND_PE_INFO = "pe-info"
SCAN_KIND_FILETYPE = "filetype"
SCAN_KIND_COMPOSITION = "composition"
SCAN_KIND_LIBRARY = "library"
SCAN_KIND_UNPACK = "unpack"
SCAN_KIND_BENCHMARK = "benchmark"
SCAN_KIND_FIRMWARE = "firmware"
SCAN_KIND_GOBUILDINFO = "gobuildinfo"
# Which FLIRT signature sets matched which symbols of a binary
# (:mod:`reportal.flirt_sigs`).  The reading is a catalog lookup, not an engine
# call, so it is stored like any other scan and never runs rebrew.
SCAN_KIND_FLIRT = "flirt"
# A read-only live-debug transcript (:mod:`reportal.debug`).  The session
# controls the sample under the debugger, so it is opt-in like detonation.
SCAN_KIND_DEBUG_SESSION = "debug-session"

# Per-section byte coverage is reportal's own metric over the stored function
# table and the stored `pe-info` section table.  The hosted portal publishes no
# equivalent, so the payload carries this label and docs/PARITY.md says so.
FUNCTION_COVERAGE_NOTE = (
    "reportal's own metric over the stored function table and the stored pe-info"
    " sections; the hosted portal publishes no per-section byte coverage"
)

# Decimal places a coverage percentage is rounded to.  One decimal matches the
# other reportal percentages (`composition._percent`); a zero-byte section and
# a binary with no stored functions report None instead of a fabricated 0.
COVERAGE_PERCENT_DIGITS = 1

# Status a stored scan carries.  A scan is written only after its engine call
# returned, so it is never pending.
SCAN_STATUS_DONE = "done"

# Statuses a `pipeline_runs` row carries.  A run is created `running` and
# finished as `done`, or `failed` when any of its steps failed.
PIPELINE_RUN_RUNNING = "running"
PIPELINE_RUN_DONE = "done"
PIPELINE_RUN_FAILED = "failed"

PIPELINE_RUN_FINISH_STATUSES: frozenset[str] = frozenset({PIPELINE_RUN_DONE, PIPELINE_RUN_FAILED})

# Statuses a `pipeline_steps` row carries.  `done` means the component ran to
# completion, `skipped` that the loader never activated it, `failed` that its
# effect raised, and `deactivated` that it was ready and then lost a
# requirement before it ran (a mid-run revoke or revert).
PIPELINE_STEP_DONE = "done"
PIPELINE_STEP_SKIPPED = "skipped"
PIPELINE_STEP_FAILED = "failed"
PIPELINE_STEP_DEACTIVATED = "deactivated"

# Engine label recorded on an analysis created to carry a scan.  An analysis
# that already exists (an import, say) is reused as-is.
SCAN_ENGINE = "rebrew-scan"

# The data-type history table's DDL, used both by the schema below and by
# ``ensure_data_type_history``: a database created before the table existed
# picks it up on first use, the way the journal and the analysis log create
# their own tables.  One definition, so the two cannot drift.
_DATA_TYPE_HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS data_type_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type_id  INTEGER NOT NULL,
    binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    previous_json TEXT NOT NULL DEFAULT 'null',
    current_json  TEXT NOT NULL DEFAULT 'null',
    source        TEXT NOT NULL DEFAULT '',
    actor         TEXT NOT NULL DEFAULT '',
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_data_type_history_type ON data_type_history(data_type_id);
"""

_SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS binaries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT UNIQUE,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0,
    format     TEXT NOT NULL DEFAULT '',
    arch       TEXT NOT NULL DEFAULT '',
    language   TEXT NOT NULL DEFAULT '',
    compiler   TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'pending',
    engine      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    finished_at TEXT,
    log         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS functions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    va           INTEGER NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    size         INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'unknown',
    name_source  TEXT NOT NULL DEFAULT '',
    confidence   REAL NOT NULL DEFAULT 0.0,
    source_path  TEXT NOT NULL DEFAULT '',
    UNIQUE (analysis_id, va)
);

CREATE TABLE IF NOT EXISTS matches (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id           INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    candidate_function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    similarity            REAL NOT NULL DEFAULT 0.0,
    confidence            REAL NOT NULL DEFAULT 0.0,
    settings_json         TEXT NOT NULL DEFAULT '',
    source_arch           TEXT NOT NULL DEFAULT '',
    candidate_arch        TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL,
    UNIQUE (function_id, candidate_function_id)
);

CREATE TABLE IF NOT EXISTS disasm_cache (
    function_id INTEGER PRIMARY KEY REFERENCES functions(id) ON DELETE CASCADE,
    text        TEXT NOT NULL,
    extent_size INTEGER NOT NULL,
    project_dir TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decompilations (
    function_id INTEGER PRIMARY KEY REFERENCES functions(id) ON DELETE CASCADE,
    code        TEXT NOT NULL,
    backend     TEXT NOT NULL,
    named       INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_artifacts (
    function_id  INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    model        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (function_id, kind)
);

CREATE TABLE IF NOT EXISTS name_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id   INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    old_name      TEXT NOT NULL DEFAULT '',
    new_name      TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    actor         TEXT NOT NULL DEFAULT '',
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    scope       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS collection_binaries (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, binary_id)
);

CREATE TABLE IF NOT EXISTS tags (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS collection_tags (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    tag_id        INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, tag_id)
);

CREATE TABLE IF NOT EXISTS binary_tags (
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (binary_id, tag_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS binary_fingerprints (
    binary_id  INTEGER PRIMARY KEY REFERENCES binaries(id) ON DELETE CASCADE,
    json       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rebrew_contexts (
    binary_id   INTEGER PRIMARY KEY REFERENCES binaries(id) ON DELETE CASCADE,
    project_dir TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS families (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL COLLATE NOCASE UNIQUE,
    aliases_json        TEXT NOT NULL DEFAULT '[]',
    notes               TEXT NOT NULL DEFAULT '',
    reference_binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    signatures_json     TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conversations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_kind TEXT NOT NULL,
    scope_id   INTEGER NOT NULL,
    title      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id  INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'running',
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    model        TEXT NOT NULL DEFAULT '',
    effects_json TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pipeline_steps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    started_at    TEXT NOT NULL DEFAULT '',
    finished_at   TEXT NOT NULL DEFAULT '',
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    provides_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_kind    TEXT NOT NULL,
    scope_id      INTEGER NOT NULL,
    author        TEXT NOT NULL,
    author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    body          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor      TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auto_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id    INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'running',
    config_json  TEXT NOT NULL DEFAULT '{}',
    stats_json   TEXT NOT NULL DEFAULT '{}',
    effects_json TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    finished_at  TEXT
);

CREATE TABLE IF NOT EXISTS auto_tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES auto_runs(id) ON DELETE CASCADE,
    parent_id   INTEGER REFERENCES auto_tasks(id) ON DELETE CASCADE,
    depth       INTEGER NOT NULL DEFAULT 0,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    function_id INTEGER REFERENCES functions(id) ON DELETE SET NULL,
    va          INTEGER,
    status      TEXT NOT NULL DEFAULT 'pending',
    worker      TEXT NOT NULL DEFAULT '',
    attempts    INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS auto_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL REFERENCES auto_tasks(id) ON DELETE CASCADE,
    attempt     INTEGER NOT NULL,
    worker      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_kind TEXT NOT NULL,
    scope_id   INTEGER NOT NULL,
    title      TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    mime       TEXT NOT NULL DEFAULT '',
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    text       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (scope_kind, scope_id, sha256)
);

CREATE TABLE IF NOT EXISTS chunks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id    INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    ordinal        INTEGER NOT NULL,
    text           TEXT NOT NULL,
    embedding_json TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id        TEXT PRIMARY KEY,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    "key"     TEXT NOT NULL,
    label     TEXT NOT NULL DEFAULT '',
    meta_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (binary_id, kind, "key")
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id        TEXT PRIMARY KEY,
    binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    source    TEXT NOT NULL,
    target    TEXT NOT NULL,
    rel       TEXT NOT NULL,
    weight    REAL NOT NULL DEFAULT 1.0,
    meta_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (binary_id, source, target, rel)
);

CREATE TABLE IF NOT EXISTS data_types (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'struct',
    namespace     TEXT NOT NULL DEFAULT '',
    size          INTEGER NOT NULL DEFAULT 0,
    members_json  TEXT NOT NULL DEFAULT '[]',
    values_json   TEXT NOT NULL DEFAULT '[]',
    target        TEXT NOT NULL DEFAULT '',
    element_count INTEGER,
    source        TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (binary_id, name)
);

CREATE TABLE IF NOT EXISTS function_signatures (
    function_id        INTEGER PRIMARY KEY REFERENCES functions(id) ON DELETE CASCADE,
    name               TEXT,
    return_type        TEXT,
    calling_convention TEXT,
    parameters_json    TEXT,
    source             TEXT,
    created_at         TEXT,
    updated_at         TEXT
);

CREATE TABLE IF NOT EXISTS signature_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id   INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    previous_json TEXT NOT NULL DEFAULT 'null',
    source        TEXT NOT NULL DEFAULT '',
    actor         TEXT NOT NULL DEFAULT '',
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL
);

-- ``(analysis_id, name_source)`` covers the imported-stubs listing and the
-- plain ``analysis_id`` filter (leftmost prefix); the older single-column
-- index is dropped so an upgrade does not keep both.
DROP INDEX IF EXISTS idx_functions_analysis;
CREATE INDEX IF NOT EXISTS idx_functions_analysis_name_source
    ON functions(analysis_id, name_source);
-- ``(binary_id, engine)`` covers find-by-engine and the plain binary listing
-- (leftmost prefix); the older single-column index is dropped so an upgrade
-- does not keep both.
DROP INDEX IF EXISTS idx_analyses_binary;
CREATE INDEX IF NOT EXISTS idx_analyses_binary_engine ON analyses(binary_id, engine);
CREATE INDEX IF NOT EXISTS idx_matches_function ON matches(function_id);
CREATE INDEX IF NOT EXISTS idx_matches_candidate ON matches(candidate_function_id);
CREATE INDEX IF NOT EXISTS idx_name_history_function ON name_history(function_id);
CREATE INDEX IF NOT EXISTS idx_signature_history_function ON signature_history(function_id);
-- ``binary_tags`` is keyed by ``(binary_id, tag_id)``; the PK already covers
-- binary_id, so only the reverse (tag delete / tag count) needs an index.
DROP INDEX IF EXISTS idx_binary_tags_binary;
CREATE INDEX IF NOT EXISTS idx_binary_tags_tag ON binary_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_collection_tags_tag ON collection_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_collection_binaries_binary ON collection_binaries(binary_id);
CREATE INDEX IF NOT EXISTS idx_feedback_user ON feedback(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_analysis_kind ON scans(analysis_id, kind);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_comments_scope ON comments(scope_kind, scope_id);
CREATE INDEX IF NOT EXISTS idx_conversations_scope ON conversations(scope_kind, scope_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_function ON pipeline_runs(function_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_steps_run ON pipeline_steps(run_id);
CREATE INDEX IF NOT EXISTS idx_auto_runs_binary ON auto_runs(binary_id);
-- At most one live auto run per (binary, config): a double-click or a
-- transport retry must reuse the running row rather than start a second
-- metered worker.  Finished runs keep every historical row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_runs_live_config
    ON auto_runs(binary_id, config_json) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_auto_tasks_run ON auto_tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_auto_tasks_parent ON auto_tasks(parent_id);
-- Unique ``(task_id, attempt)`` replaces the plain task index and stops a
-- double-write of the same attempt number.  Attempt numbers are a per-task
-- sequence (see ``auto_store.add_auto_attempt``), not a per-function retry
-- index, so a multi-function batch does not collide on attempt 1.
DROP INDEX IF EXISTS idx_auto_attempts_task;
CREATE UNIQUE INDEX IF NOT EXISTS idx_auto_attempts_task_attempt
    ON auto_attempts(task_id, attempt);
CREATE INDEX IF NOT EXISTS idx_documents_scope ON documents(scope_kind, scope_id);
-- Unique ``(document_id, ordinal)`` replaces the plain document index and
-- makes a repeated ordinal unrepresentable.
DROP INDEX IF EXISTS idx_chunks_document;
CREATE UNIQUE INDEX IF NOT EXISTS idx_chunks_document_ordinal
    ON chunks(document_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_binary ON graph_nodes(binary_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_binary ON graph_edges(binary_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target);
CREATE INDEX IF NOT EXISTS idx_families_reference ON families(reference_binary_id);
CREATE INDEX IF NOT EXISTS idx_data_types_binary ON data_types(binary_id);
-- Dashboard series filter analyses and auto runs by created_at window.
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_auto_runs_created_at ON auto_runs(created_at);
-- Health ``matched`` count filters functions by status.
CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(status);
"""
    + _DATA_TYPE_HISTORY_DDL
)


# How long a connection waits for a write lock before raising ``sqlite3.OperationalError``.
# Concurrent writers (API requests, jobs, auto-mode workers) share one file; without
# a timeout the default is fail-immediate, which surfaces as a 500 under load.
# Auto mode raises the same value on its own connections; setting it here covers
# every other open path.
BUSY_TIMEOUT_MS = 30_000

# Journal mode every connection uses. WAL lets readers proceed while a writer
# holds the lock, so two users on the same workspace do not block each other.
# Set on every open rather than once at init: the mode is persistent, but a
# database created before this shipped still runs in rollback mode until each
# connection switches it. Best effort; a reader on an unreadable path still
# answers through its own error path.
JOURNAL_MODE = "WAL"


def connect(db_path: Path) -> sqlite3.Connection:
    """Open *db_path* read-write with row access by name and FKs enforced."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute(f"PRAGMA journal_mode = {JOURNAL_MODE}")
    return conn


def open_db() -> sqlite3.Connection:
    """Open the workspace database, creating or upgrading the schema as needed.

    Shared by the HTTP, CLI and MCP surfaces so none of them reach through the
    FastAPI module for a connection.
    """
    path = workspace_db_path()
    init_db(path)
    return connect(path)


# Columns a release added to a table after the first one.  ``CREATE TABLE IF
# NOT EXISTS`` leaves an existing database's tables alone, so a column an older
# reportal.db lacks is added by name here.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("auto_runs", "effects_json", "TEXT NOT NULL DEFAULT '[]'"),
    # The type model's declaration shape.  A row that predates these columns
    # was written by the structs-scan import, which only ever recovered
    # ``typedef struct`` definitions, so ``struct`` is the one defensible
    # default and the migration never invents another kind.
    ("data_types", "kind", "TEXT NOT NULL DEFAULT 'struct'"),
    ("data_types", "namespace", "TEXT NOT NULL DEFAULT ''"),
    ("data_types", "values_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("data_types", "target", "TEXT NOT NULL DEFAULT ''"),
    ("data_types", "element_count", "INTEGER"),
    # The run settings a match row was produced under.  A row written before
    # this column existed was recorded outside a match run, so the empty
    # default reads as "no recorded settings" rather than an invented scope.
    ("matches", "settings_json", "TEXT NOT NULL DEFAULT ''"),
    # The ISA pair a match row compared.  A row written before these columns
    # existed has no recorded architectures, so the empty default reads as
    # "unknown" rather than an invented ISA.
    ("matches", "source_arch", "TEXT NOT NULL DEFAULT ''"),
    ("matches", "candidate_arch", "TEXT NOT NULL DEFAULT ''"),
    # The inputs a scan ran with.  A stored scan is its result; the caller-named
    # input behind an engine result is not part of it (the engine's payload is
    # stored as it came back), so without this column the scan that produced a
    # reading cannot be replayed with the same parameters.
    ("scans", "params_json", "TEXT NOT NULL DEFAULT '{}'"),
    # The last time a collection's own fields, its membership or its tags
    # changed.  A row that predates the column takes its creation time below,
    # so the sort never puts an untouched collection before a touched one.
    ("collections", "updated_at", "TEXT NOT NULL DEFAULT ''"),
    # Whether the stored decompilation was produced with symbol names applied.
    # A row that predates the column was written before the flag was kept, so
    # the default is false rather than inventing that names were applied.
    ("decompilations", "named", "INTEGER NOT NULL DEFAULT 0"),
    # Which team owns a binary or a collection, and whether the rest of the
    # workspace may see it.  A row that predates the columns is public and
    # ownerless, which is what every pre-team install meant.
    ("binaries", "owner_team_id", "INTEGER"),
    ("binaries", "visibility", "TEXT NOT NULL DEFAULT 'public'"),
    ("collections", "owner_team_id", "INTEGER"),
    ("collections", "visibility", "TEXT NOT NULL DEFAULT 'public'"),
    # The model an analysis last ran under (``models.py``).  A row that
    # predates the column was written before the registry existed, so the empty
    # default reads as "no model recorded" rather than an invented one.
    ("analyses", "model", "TEXT NOT NULL DEFAULT ''"),
    # A team member's role inside the team, and the team a user has switched to.
    # A membership that predates the column was created before team roles
    # existed, and the only role every such install had was the equal member, so
    # ``member`` is the one defensible default; no active team means the caller
    # sees every team it belongs to, which is what every pre-switch install did.
    ("team_members", "role", "TEXT NOT NULL DEFAULT 'member'"),
    ("users", "active_team_id", "INTEGER"),
    # The organisation a team belongs to.  A team that predates the hierarchy
    # belongs to none, which is what a standalone install meant.
    ("teams", "organisation_id", "INTEGER"),
    # The engine inputs a cached listing was produced from.  A row that predates
    # these columns has no recorded identity, so the backfill below drops it
    # rather than serving a listing that may no longer match the live extent
    # or project directory.
    ("disasm_cache", "extent_size", "INTEGER NOT NULL DEFAULT -1"),
    ("disasm_cache", "project_dir", "TEXT NOT NULL DEFAULT ''"),
    # The stable user id behind a display name.  A row that predates the column
    # was written before the id was kept, so NULL reads as "name only" rather
    # than an invented identity.
    ("name_history", "actor_user_id", "INTEGER"),
    ("signature_history", "actor_user_id", "INTEGER"),
    ("data_type_history", "actor_user_id", "INTEGER"),
    ("comments", "author_user_id", "INTEGER"),
    # The recovered source language of a binary (Go, Rust, ...). A row that
    # predates the column has none recorded, so the empty default reads as
    # "unknown" rather than an invented language.
    ("binaries", "language", "TEXT NOT NULL DEFAULT ''"),
    # Recovered toolchain (MSVC, MinGW, ...). A row that predates the
    # column has none recorded, so the empty default reads as unknown.
    ("binaries", "compiler", "TEXT NOT NULL DEFAULT ''"),
    # Operator note on a binary. A row that predates the column has none,
    # so the empty default reads as no note rather than invented text.
    ("binaries", "notes", "TEXT NOT NULL DEFAULT ''"),
    # An operator's hand-set format and ISA for a binary. A row that predates
    # the columns was never corrected, so the empty default reads as
    # "detection stands" and the stored format/arch answer every read.
    ("binaries", "format_override", "TEXT NOT NULL DEFAULT ''"),
    ("binaries", "arch_override", "TEXT NOT NULL DEFAULT ''"),
    # Invite TTL. A row that predates the column has none recorded, so the
    # empty default derives from created_at + INVITE_TTL_SECONDS at redeem.
    ("team_invites", "expires_at", "TEXT NOT NULL DEFAULT ''"),
    # Last time a named extra key authenticated. A row that predates the
    # column has never been seen, so the empty default reads as never.
    ("user_api_keys", "last_used_at", "TEXT NOT NULL DEFAULT ''"),
    # Named-key write flag. A row that predates the column is a full key,
    # so the default 0 matches what those tokens already did.
    ("user_api_keys", "read_only", "INTEGER NOT NULL DEFAULT 0"),
    # Last time the login token authenticated. A row that predates the
    # column has never been seen, so the empty default reads as never.
    ("users", "last_used_at", "TEXT NOT NULL DEFAULT ''"),
)

# Statements run after the columns above are added, to fill what an existing
# database could not know.  Each is idempotent, so running it again is a no-op.
_BACKFILLS: tuple[str, ...] = (
    "UPDATE collections SET updated_at = created_at WHERE updated_at = ''",
    "DELETE FROM disasm_cache WHERE extent_size < 0",
)

# Indexes that need a column `_ADDED_COLUMNS` (or auth) creates first.  The main
# `_SCHEMA` script runs before those columns exist, so these land here after
# the ALTER ADD COLUMN pass; `IF NOT EXISTS` keeps a fresh database and an
# upgrade of an old one on the same path.  The table name is checked so a
# partial fixture that never created `users` does not fail the upgrade.  An
# optional required column skips the statement when a stub table predates it
# (the null-sha256 name/path index needs `binaries.sha256`).
_ADDED_INDEXES: tuple[tuple[str, str | None, str], ...] = (
    (
        "binaries",
        None,
        "CREATE INDEX IF NOT EXISTS idx_binaries_owner_team ON binaries(owner_team_id)",
    ),
    (
        "collections",
        None,
        "CREATE INDEX IF NOT EXISTS idx_collections_owner_team ON collections(owner_team_id)",
    ),
    ("users", None, "CREATE INDEX IF NOT EXISTS idx_users_active_team ON users(active_team_id)"),
)

# Unique ``(name, path)`` for rows with no content hash.  Built after a
# duplicate collapse so an upgrade of a database that raced before the
# constraint existed can still take the index.
_NULL_SHA_UNIQUE_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_binaries_name_path_null_sha"
    " ON binaries(name, path) WHERE sha256 IS NULL"
)


def _upgrade_null_sha_unique(conn: sqlite3.Connection) -> None:
    """Collapse raced null-sha binaries, then enforce unique ``(name, path)``."""
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'binaries'"
    ).fetchone():
        return
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}
    if "sha256" not in columns:
        return
    duplicates = conn.execute(
        "SELECT name, path, MIN(id) AS keep_id FROM binaries"
        " WHERE sha256 IS NULL GROUP BY name, path HAVING COUNT(*) > 1"
    ).fetchall()
    for row in duplicates:
        conn.execute(
            "DELETE FROM binaries WHERE sha256 IS NULL AND name = ? AND path = ? AND id != ?",
            (row["name"], row["path"], int(row["keep_id"])),
        )
    conn.execute("DROP INDEX IF EXISTS idx_binaries_name_path_null_sha")
    conn.execute(_NULL_SHA_UNIQUE_INDEX)


def _upgrade_schema(conn: sqlite3.Connection) -> None:
    """Add the columns an existing database predates; a fresh one has them all."""
    for table, column, declaration in _ADDED_COLUMNS:
        existing = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
    for statement in _BACKFILLS:
        conn.execute(statement)
    for table, required_column, statement in _ADDED_INDEXES:
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone():
            continue
        if required_column is not None:
            columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
            if required_column not in columns:
                continue
        conn.execute(statement)
    _upgrade_null_sha_unique(conn)
    conn.commit()


def init_db(db_path: Path) -> None:
    """Create the schema in *db_path*, creating parent directories as needed."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(connect(db_path)) as conn:
        conn.executescript(_SCHEMA)
        # The identity and log tables come first: the column upgrade below
        # touches tables they create, so a fresh database has to carry them
        # before it runs.
        auth.ensure_schema(conn)
        analysis_log.ensure_schema(conn)
        # Metering adds columns to the organisations table auth just created,
        # so it follows identity and precedes the generic column upgrade.
        metering.ensure_schema(conn)
        # The FLIRT catalog imports this module for its clock, so it is
        # imported here rather than at the top: the cycle is broken by loading
        # it after the clock exists.
        from reportal import flirt_sigs

        flirt_sigs.ensure_schema(conn)
        _upgrade_schema(conn)


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(row) for row in cursor.fetchall()]


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards in *value*; callers add ``ESCAPE '\\'``."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ── Binaries ───────────────────────────────────────────────────────


def _find_binary(
    conn: sqlite3.Connection, *, sha256: str | None, name: str, path: str
) -> int | None:
    """Return the id of a matching binary row, or None.

    A known ``sha256`` identifies the binary by content.  Without one (an
    import whose target binary is not on disk), identity falls back to the
    ``(name, path)`` pair, which is stable for repeated imports of the same
    source workspace.
    """
    if sha256:
        row = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM binaries WHERE sha256 IS NULL AND name = ? AND path = ?",
            (name, path),
        ).fetchone()
    return int(row["id"]) if row else None


def add_binary(
    conn: sqlite3.Connection,
    *,
    sha256: str | None,
    name: str,
    path: str = "",
    size: int = 0,
    fmt: str = "",
    arch: str = "",
) -> int:
    """Insert a binary, returning the existing id when it is already known.

    Dedupe is by ``sha256`` when supplied, else by ``(name, path)`` (see
    :func:`_find_binary`).  ``sha256`` stays NULL when the binary bytes are
    not available, so two unknown binaries never collide on an empty string.
    The insert is atomic: two concurrent uploads of the same bytes race on
    the UNIQUE ``sha256`` index, and two concurrent imports of the same
    off-disk ``(name, path)`` race on the partial unique null-sha index; the
    loser reads back the winner's row instead of raising ``IntegrityError``.
    The display name is NFC-normalized so an NFD upload name (typical of
    macOS) matches a later NFC rename of the same spelling when sha256 is
    absent and dedupe falls back to ``(name, path)``.
    """
    name = unicodedata.normalize("NFC", name)
    if sha256:
        conn.execute(
            "INSERT OR IGNORE INTO binaries (sha256, name, path, size, format, arch, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sha256, name, path, size, fmt, arch, now()),
        )
        conn.commit()
        existing = _find_binary(conn, sha256=sha256, name=name, path=path)
        assert existing is not None, "the row was just inserted"
        return existing
    existing = _find_binary(conn, sha256=None, name=name, path=path)
    if existing is not None:
        return existing
    try:
        cur = conn.execute(
            "INSERT INTO binaries (sha256, name, path, size, format, arch, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (None, name, path, size, fmt, arch, now()),
        )
    except sqlite3.IntegrityError:
        existing = _find_binary(conn, sha256=None, name=name, path=path)
        if existing is not None:
            return existing
        raise
    conn.commit()
    return int(cur.lastrowid or 0)


def find_binary_by_sha256(conn: sqlite3.Connection, sha256: str) -> dict[str, Any] | None:
    """One binary row by content hash, or None.

    Uploads resolve dedupe with this before publishing a file, so a repeated
    upload returns the row already stored instead of adding a second one.
    """
    binary_id = _find_binary(conn, sha256=sha256, name="", path="")
    return get_binary(conn, binary_id) if binary_id is not None else None


# The orders the register listing offers; `id` is the insertion order it always
# used, so it stays the default.  The names match the analyses list's, where the
# two controls mean the same thing.
BINARY_ORDERS: dict[str, str] = {
    "id": "b.id ASC",
    "newest": "b.id DESC",
    "name": "b.name COLLATE NOCASE ASC, b.id ASC",
    "name-desc": "b.name COLLATE NOCASE DESC, b.id DESC",
    "size": "b.size ASC, b.id ASC",
    "size-desc": "b.size DESC, b.id ASC",
}

DEFAULT_BINARY_ORDER = "id"

# Largest page the register takes. A caller that names no limit still reads the
# whole register, which is what the CLI, the MCP tools and `related.py` rely on.
MAX_BINARY_LIMIT = 1000


def list_binaries(
    conn: sqlite3.Connection,
    *,
    search: str | None = None,
    tag: str | None = None,
    fmt: str | None = None,
    language: str | None = None,
    compiler: str | None = None,
    order: str = DEFAULT_BINARY_ORDER,
    visible_to: Mapping[str, Any] | None = None,
    summary: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """The binaries, in *order*, each with its function and comment counts.

    *search* matches the binary's name, its SHA-256 (a prefix is enough, which
    is what an analyst has for a sample they know by hash) or its operator
    notes; *tag* keeps the
    binaries carrying that exact tag name; *fmt* keeps one stored format, which
    is the crawler's own reading rather than a vocabulary written down twice;
    *language* keeps one recovered source language; *compiler* one recovered
    toolchain.  *order* is one of
    :data:`BINARY_ORDERS`; an unknown one raises ``ValueError``, which the API,
    the CLI and the MCP tools map to their own error vocabulary.

    *visible_to* is the authenticated caller (None while auth is off); a
    non-admin caller sees only the public binaries and its own teams', which is
    what `auth.visible_clause` expresses.

    *summary* projects each row down to its ``id`` and ``name``, which is what a
    picker that offers the whole register needs: the full row carries the
    sha256, the operator notes and both aggregate counts, so a twenty-thousand
    sample register costs megabytes of JSON for two columns a select renders.

    *limit* and *offset* cut one page out of the register, bounded by
    :data:`MAX_BINARY_LIMIT`; ``limit`` None (the default) reads every row, which
    is what a caller that walks the register whole wants.  The page is cut after
    the order is applied, so two pages of one filter set do not repeat a row.
    """
    if order not in BINARY_ORDERS:
        raise ValueError(f"unknown binary order: {order}")
    if limit is not None and not 1 <= limit <= MAX_BINARY_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_BINARY_LIMIT}")
    if offset < 0:
        raise ValueError(f"offset must not be negative, got {offset}")
    if summary:
        sql = "SELECT b.id AS id, b.name AS name FROM binaries b"
    elif limit is not None:
        # A page wants the counts of its own rows: the aggregate join below
        # groups the whole functions table before LIMIT is applied, which
        # measures at 10ms over 200k functions for 200 rows, where the
        # correlated form asks the two indices once per row.
        sql = """
        SELECT b.*,
               (SELECT COUNT(*) FROM functions f JOIN analyses a ON f.analysis_id = a.id
                WHERE a.binary_id = b.id) AS function_count,
               (SELECT COUNT(*) FROM comments c
                WHERE c.scope_kind = 'binary' AND c.scope_id = b.id) AS comment_count
        FROM binaries b
    """
    else:
        # Aggregate counts once per table rather than with a correlated subquery
        # per binary: a register of hundreds of samples otherwise rescans
        # functions/comments once per row.
        sql = """
        SELECT b.*, COALESCE(fc.function_count, 0) AS function_count,
               COALESCE(cc.comment_count, 0) AS comment_count
        FROM binaries b
        LEFT JOIN (
            SELECT a.binary_id AS binary_id, COUNT(*) AS function_count
            FROM functions f
            JOIN analyses a ON f.analysis_id = a.id
            GROUP BY a.binary_id
        ) fc ON fc.binary_id = b.id
        LEFT JOIN (
            SELECT c.scope_id AS binary_id, COUNT(*) AS comment_count
            FROM comments c
            WHERE c.scope_kind = 'binary'
            GROUP BY c.scope_id
        ) cc ON cc.binary_id = b.id
    """
    where, params = _binary_where(
        conn,
        search=search,
        tag=tag,
        fmt=fmt,
        language=language,
        compiler=compiler,
        visible_to=visible_to,
    )
    sql += where
    sql += f" ORDER BY {BINARY_ORDERS[order]}"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params.extend((limit, offset))
    return _rows(conn.execute(sql, params))


def _binary_where(
    conn: sqlite3.Connection,
    *,
    search: str | None,
    tag: str | None,
    fmt: str | None,
    language: str | None,
    compiler: str | None,
    visible_to: Mapping[str, Any] | None,
) -> tuple[str, list[Any]]:
    """The shared WHERE of the register listing and its count.

    Returned as the clause text (empty when nothing filters) plus its
    parameters, so :func:`list_binaries` and :func:`count_binaries` cannot
    drift: a page total has to count the same predicate the page was cut from.
    """
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clauses.append(scope[0])
        params.extend(scope[1])
    if search:
        pattern = _escape_like(search)
        clauses.append(
            "(b.name LIKE ? ESCAPE '\\' OR b.sha256 LIKE ? ESCAPE '\\'"
            " OR b.notes LIKE ? ESCAPE '\\')"
        )
        params.extend((pattern, pattern, pattern))
    if tag:
        clauses.append(
            "EXISTS (SELECT 1 FROM binary_tags bt JOIN tags t ON t.id = bt.tag_id"
            " WHERE bt.binary_id = b.id AND t.name = ?)"
        )
        params.append(tag)
    if fmt:
        # A hand-set override answers reads first, so the filter matches what
        # the binary header shows rather than the detection it replaced.  An
        # old database without the column still filters on detection.
        columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}
        clauses.append(
            "COALESCE(NULLIF(b.format_override, ''), b.format) = ?"
            if "format_override" in columns
            else "b.format = ?"
        )
        params.append(fmt)
    if language:
        clauses.append("b.language = ?")
        params.append(language)
    if compiler:
        clauses.append("b.compiler = ?")
        params.append(compiler)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def count_binaries(
    conn: sqlite3.Connection,
    *,
    search: str | None = None,
    tag: str | None = None,
    fmt: str | None = None,
    language: str | None = None,
    compiler: str | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> int:
    """How many binaries the same filters :func:`list_binaries` takes keep."""
    where, params = _binary_where(
        conn,
        search=search,
        tag=tag,
        fmt=fmt,
        language=language,
        compiler=compiler,
        visible_to=visible_to,
    )
    row = conn.execute("SELECT COUNT(*) AS total FROM binaries b" + where, params).fetchone()
    return int(row["total"]) if row is not None else 0


def binary_filter_values(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """The formats, languages and compilers the register actually holds.

    Distinct column reads the way the analyses facets are, so the control
    offers only values that can match something.  The format facet reads the
    effective value (a hand-set override first), like the `?format=` filter.
    """

    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}

    def distinct(column: str, effective: str = "") -> list[str]:
        read = effective if effective and f"{column}_override" in columns else f"b.{column}"
        rows = conn.execute(
            f"SELECT DISTINCT {read} AS value FROM binaries b"
            f" WHERE {read} IS NOT NULL AND {read} != '' ORDER BY {read}"
        )
        return [str(row["value"]) for row in rows]

    return {
        "formats": distinct("format", "COALESCE(NULLIF(b.format_override, ''), b.format)"),
        "languages": distinct("language"),
        "compilers": distinct("compiler"),
    }


def set_binary_language(
    conn: sqlite3.Connection,
    binary_id: int,
    language: str,
    *,
    overwrite: bool = False,
) -> None:
    """Record the recovered source language of *binary_id*.

    An empty *language* is ignored.  Without *overwrite*, a binary that
    already carries a language keeps it, so a later weaker guess cannot
    replace a stronger stamp (Go buildinfo over a filetype heuristic).
    """
    value = language.strip()
    if not value:
        return
    if overwrite:
        conn.execute("UPDATE binaries SET language = ? WHERE id = ?", (value, binary_id))
    else:
        conn.execute(
            "UPDATE binaries SET language = ? WHERE id = ? AND language = ''",
            (value, binary_id),
        )
    conn.commit()


def set_binary_compiler(
    conn: sqlite3.Connection,
    binary_id: int,
    compiler: str,
    *,
    overwrite: bool = False,
) -> None:
    """Record the recovered toolchain of *binary_id*.

    An empty *compiler* is ignored.  Without *overwrite*, a binary that
    already carries a toolchain keeps it.
    """
    value = compiler.strip()
    if not value:
        return
    if overwrite:
        conn.execute("UPDATE binaries SET compiler = ? WHERE id = ?", (value, binary_id))
    else:
        conn.execute(
            "UPDATE binaries SET compiler = ? WHERE id = ? AND compiler = ''",
            (value, binary_id),
        )
    conn.commit()


def rename_binary(conn: sqlite3.Connection, binary_id: int, name: str) -> dict[str, Any] | None:
    """Set the display name of *binary_id*; None when the id is unknown.

    The name is stripped and NFC-normalized.  An empty value raises
    ``ValueError``.  Dedupe stays on sha256, so two binaries may share a
    display name.
    """
    cleaned = unicodedata.normalize("NFC", name.strip())
    if not cleaned:
        raise ValueError("binary name must not be empty")
    if get_binary(conn, binary_id) is None:
        return None
    conn.execute("UPDATE binaries SET name = ? WHERE id = ?", (cleaned, binary_id))
    conn.commit()
    return get_binary(conn, binary_id)


MAX_BINARY_NOTES = 2000


def set_binary_notes(conn: sqlite3.Connection, binary_id: int, notes: str) -> dict[str, Any] | None:
    """Set the operator note on *binary_id*; None when the id is unknown.

    The note is stripped.  Empty is allowed (clears the note).  A value
    past :data:`MAX_BINARY_NOTES` raises ``ValueError``.
    """
    cleaned = notes.strip()
    if len(cleaned) > MAX_BINARY_NOTES:
        raise ValueError(f"binary notes must be at most {MAX_BINARY_NOTES} characters")
    if get_binary(conn, binary_id) is None:
        return None
    conn.execute("UPDATE binaries SET notes = ? WHERE id = ?", (cleaned, binary_id))
    conn.commit()
    return get_binary(conn, binary_id)


def set_binary_format_override(
    conn: sqlite3.Connection, binary_id: int, *, format_override: str = "", arch_override: str = ""
) -> dict[str, Any] | None:
    """Set the operator's hand-set format and ISA on *binary_id*; None when unknown.

    Each value is stripped and empty clears that override, so detection stands
    again.  Vocabulary is the caller's job (the upload options); the store
    keeps whatever spelling it is given.
    """
    if get_binary(conn, binary_id) is None:
        return None
    conn.execute(
        "UPDATE binaries SET format_override = ?, arch_override = ? WHERE id = ?",
        (format_override.strip(), arch_override.strip(), binary_id),
    )
    conn.commit()
    return get_binary(conn, binary_id)


def effective_format(row: Mapping[str, Any]) -> str:
    """The format a binary row answers with: the override, else detection."""
    return str(row.get("format_override") or row.get("format") or "")


def effective_arch(row: Mapping[str, Any]) -> str:
    """The ISA a binary row answers with: the override, else detection."""
    return str(row.get("arch_override") or row.get("arch") or "")


def get_binary(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """One binary row with its function count, or None."""
    cur = conn.execute(
        """
        SELECT b.*, (
            SELECT COUNT(*) FROM functions f
            JOIN analyses a ON f.analysis_id = a.id
            WHERE a.binary_id = b.id
        ) AS function_count
        FROM binaries b WHERE b.id = ?
        """,
        (binary_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def set_fingerprint(conn: sqlite3.Connection, binary_id: int, data: dict[str, Any]) -> None:
    """Store the engine fingerprint of *binary_id*, replacing any earlier one."""
    conn.execute(
        "INSERT INTO binary_fingerprints (binary_id, json, created_at) VALUES (?, ?, ?)"
        " ON CONFLICT(binary_id) DO UPDATE SET json = excluded.json,"
        " created_at = excluded.created_at",
        (binary_id, json.dumps(data), now()),
    )
    conn.commit()


def get_fingerprint(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Return the stored fingerprint of *binary_id*, or None."""
    row = conn.execute(
        "SELECT json FROM binary_fingerprints WHERE binary_id = ?", (binary_id,)
    ).fetchone()
    if row is None:
        return None
    try:
        stored = json.loads(str(row["json"]))
    except json.JSONDecodeError:
        return None
    return stored if isinstance(stored, dict) else None


# ── Rebrew project contexts ────────────────────────────────────────


def set_rebrew_context(conn: sqlite3.Connection, binary_id: int, project_dir: str) -> None:
    """Store the rebrew project directory backing *binary_id*, replacing any earlier one.

    A changed project directory is a different engine input for every function of
    the binary, so the disassembly cache for those functions is dropped together
    with stored decompilations and AI artifacts that came from the previous
    project; the first context set (``None`` to a path) is the same change for
    rows recorded against the empty identity.  A write that keeps the same path
    leaves those alone.
    """
    previous = get_rebrew_context(conn, binary_id)
    conn.execute(
        "INSERT INTO rebrew_contexts (binary_id, project_dir) VALUES (?, ?)"
        " ON CONFLICT(binary_id) DO UPDATE SET project_dir = excluded.project_dir",
        (binary_id, project_dir),
    )
    conn.commit()
    # ``previous is None`` is a live identity change too: listings and
    # decompilations recorded against the empty project_dir must not survive
    # the first real context.  Same-path refreshes leave derived rows alone.
    if previous != project_dir:
        clear_disasm_for_binary(conn, binary_id)
        conn.execute(
            "DELETE FROM decompilations WHERE function_id IN ("
            " SELECT f.id FROM functions f"
            " JOIN analyses a ON a.id = f.analysis_id"
            " WHERE a.binary_id = ?)",
            (binary_id,),
        )
        conn.execute(
            "DELETE FROM ai_artifacts WHERE function_id IN ("
            " SELECT f.id FROM functions f"
            " JOIN analyses a ON a.id = f.analysis_id"
            " WHERE a.binary_id = ?)",
            (binary_id,),
        )
        conn.commit()


def get_rebrew_context(conn: sqlite3.Connection, binary_id: int) -> str | None:
    """Return the rebrew project directory of *binary_id*, or None."""
    row = conn.execute(
        "SELECT project_dir FROM rebrew_contexts WHERE binary_id = ?", (binary_id,)
    ).fetchone()
    return str(row["project_dir"]) if row else None


# ── Malware families ───────────────────────────────────────────────


def _family_row(row: sqlite3.Row) -> dict[str, Any]:
    """One family row with its aliases and derived signature bundle parsed."""
    aliases = [value for value in _json_list(row["aliases_json"]) if isinstance(value, str)]
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "aliases": aliases,
        "notes": str(row["notes"]),
        "reference_binary_id": int(row["reference_binary_id"]),
        "signatures": _json_dict(row["signatures_json"]),
        "created_at": str(row["created_at"]),
    }


def add_family(
    conn: sqlite3.Connection,
    *,
    name: str,
    aliases: Sequence[str],
    notes: str,
    reference_binary_id: int,
    signatures: dict[str, Any],
) -> int:
    """Insert a family with its derived signature bundle; returns its id.

    The name column is ``COLLATE NOCASE UNIQUE``, so a case-insensitive repeat
    raises :class:`sqlite3.IntegrityError`.
    """
    cur = conn.execute(
        "INSERT INTO families"
        " (name, aliases_json, notes, reference_binary_id, signatures_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            name,
            json.dumps(list(aliases)),
            notes,
            reference_binary_id,
            json.dumps(signatures),
            now(),
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_families(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every family, name order (case-insensitive), each with its aliases and bundle."""
    cur = conn.execute("SELECT * FROM families ORDER BY name COLLATE NOCASE")
    return [_family_row(row) for row in cur.fetchall()]


def get_family(conn: sqlite3.Connection, family_id: int) -> dict[str, Any] | None:
    """One family by id, or None."""
    row = conn.execute("SELECT * FROM families WHERE id = ?", (family_id,)).fetchone()
    return _family_row(row) if row else None


def find_family_by_name(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One family by name, case-insensitively, or None.

    The query is NFC-normalized so an NFD spelling matches the stored form
    the same way :func:`reportal.families.register_family` writes it.
    """
    cleaned = unicodedata.normalize("NFC", name.strip())
    row = conn.execute(
        "SELECT * FROM families WHERE name = ? COLLATE NOCASE", (cleaned,)
    ).fetchone()
    return _family_row(row) if row else None


def delete_family(conn: sqlite3.Connection, family_id: int) -> bool:
    """Delete a family; False when the id is unknown."""
    cur = conn.execute("DELETE FROM families WHERE id = ?", (family_id,))
    conn.commit()
    return cur.rowcount > 0


# ── Analyses ───────────────────────────────────────────────────────

# Sort orders `list_analyses` accepts, and the bound it applies when the
# caller names none.  A page is bounded so a listing route cannot be asked for
# an unbounded result.
DEFAULT_ANALYSIS_ORDER = "newest"
# The orders the hosted portal's Order control offers: the newest or oldest
# first, and the binary's name or size either way.  `list_analyses` turns a pair
# into one ORDER BY, so a listing route cannot be asked for a column it does not
# have.
ANALYSIS_ORDERS: tuple[str, ...] = (
    "newest",
    "oldest",
    "name",
    "name-desc",
    "size",
    "size-desc",
)
_ANALYSIS_ORDER_SQL: dict[str, str] = {
    "newest": "a.id DESC",
    "oldest": "a.id ASC",
    "name": "b.name ASC, a.id DESC",
    "name-desc": "b.name DESC, a.id DESC",
    "size": "b.size ASC, a.id DESC",
    "size-desc": "b.size DESC, a.id DESC",
}
# The analyses list's workspace filter, which reads the owning binary's scope the
# way the hosted portal's three controls do: an object no team owns, one a team
# does, and one the whole workspace may see.
WORKSPACE_PERSONAL = "personal"
WORKSPACE_TEAM = "team"
WORKSPACE_PUBLIC = "public"
WORKSPACE_FILTERS: tuple[str, ...] = (WORKSPACE_PERSONAL, WORKSPACE_TEAM, WORKSPACE_PUBLIC)

DEFAULT_ANALYSIS_LIMIT = 100
MAX_ANALYSIS_LIMIT = 1000


def create_analysis(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: str,
    status: str = ANALYSIS_STATUS_PENDING,
    log: str = "",
) -> int:
    """Insert an analysis for *binary_id*; returns its id.

    *status* must be one of :data:`ANALYSIS_STATUSES`, and a terminal one is
    stamped finished at once (an analysis created `done` is not an open one).
    The creation is the first entry in the analysis's log; *log* (the
    importer's summary sentence) is appended as a second one when it is given.
    """
    if status not in ANALYSIS_STATUSES:
        raise ValueError(f"unknown analysis status: {status}")
    finished_at = now() if status in TERMINAL_STATUSES else None
    # Ensure the log table exists before the INSERT: ``executescript`` commits,
    # and must not cut the analysis row off from the creation log entries.
    analysis_log.ensure_schema(conn)
    cur = conn.execute(
        "INSERT INTO analyses (binary_id, status, engine, created_at, finished_at, log)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (binary_id, status, engine, now(), finished_at, log),
    )
    analysis_id = int(cur.lastrowid or 0)
    analysis_log.append_entry(
        conn,
        analysis_id,
        message=f"analysis created for binary {binary_id} (engine {engine or 'manual'},"
        f" status {status})",
        commit=False,
    )
    if log:
        analysis_log.append_entry(conn, analysis_id, message=log, commit=False)
    conn.commit()
    return analysis_id


def find_analysis(
    conn: sqlite3.Connection, *, binary_id: int, engine: str
) -> dict[str, Any] | None:
    """Newest analysis of *binary_id* produced by *engine*, or None."""
    cur = conn.execute(
        "SELECT * FROM analyses WHERE binary_id = ? AND engine = ? ORDER BY id DESC LIMIT 1",
        (binary_id, engine),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def latest_analysis_for_binary(conn: sqlite3.Connection, binary_id: int) -> int | None:
    """Newest analysis id of *binary_id*, or None when it has none."""
    row = conn.execute(
        "SELECT id FROM analyses WHERE binary_id = ? ORDER BY id DESC LIMIT 1",
        (binary_id,),
    ).fetchone()
    return int(row["id"]) if row else None


def ensure_analysis_for_binary(conn: sqlite3.Connection, binary_id: int, *, engine: str) -> int:
    """Return the newest analysis of *binary_id*, creating one when there is none.

    A scan hangs off an analysis, so a binary registered without an import
    still gets a row to carry it.  *engine* labels the analysis only when this
    creates it.
    """
    existing = latest_analysis_for_binary(conn, binary_id)
    if existing is not None:
        return existing
    return create_analysis(conn, binary_id=binary_id, engine=engine)


def analysis_detail(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """One analysis with the counts a detail read renders; None when unknown.

    The row itself, its function and scan counts, its log entry count by
    severity and the owning binary's tags, which is what the hosted ``basic``
    read answers in one call.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return None
    binary_id = int(analysis["binary_id"])
    detail = dict(analysis)
    detail["function_count"] = count_functions(conn, analysis_id=analysis_id)
    scans = list_scans(conn, analysis_id)
    detail["scan_count"] = len(scans)
    detail["scans"] = [{"kind": row["kind"], "status": row["status"]} for row in scans]
    detail["log_count"] = analysis_log.count_entries(conn, analysis_id)
    detail["tags"] = [str(tag["name"]) for tag in get_binary_tags(conn, binary_id)]
    detail["binary_tags_are_analysis_tags"] = True
    return detail


def analysis_params(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """What a re-run of *analysis_id* would need, recorded rather than guessed.

    reportal records no parameter blob, so this reads what the tables hold: the
    engine label, the creation time, the binary with its content hash, size,
    format and architecture, the rebrew project context the engine calls resolve
    against, and the scan kinds the analysis already carries.  A re-run is
    reproducible from those, and a caller can tell what is missing (no project
    context, no scans) instead of assuming it.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return None
    binary = get_binary(conn, int(analysis["binary_id"]))
    scans = list_scans(conn, analysis_id)
    return {
        "analysis_id": analysis_id,
        "binary_id": analysis["binary_id"],
        "engine": analysis["engine"],
        "status": analysis["status"],
        "created_at": analysis["created_at"],
        "finished_at": analysis["finished_at"],
        "binary": None
        if binary is None
        else {
            "id": int(binary["id"]),
            "name": str(binary["name"]),
            "sha256": str(binary["sha256"]),
            "size": int(binary["size"] or 0),
            "format": binary["format"],
            "arch": binary["arch"],
            "path": str(binary["path"]),
        },
        "rebrew_project": get_rebrew_context(conn, int(analysis["binary_id"])),
        "scans": [str(row["kind"]) for row in scans],
    }


def analysis_status(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """The lifecycle read: the status, its times, the scans and the log counts.

    ``scans`` counts the stored scans by their own status, so a run that failed
    halfway reads differently from one that has not started, and ``logs`` counts
    the log entries by severity, which is what a reader looks at first.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return None
    scans = list_scans(conn, analysis_id)
    by_scan_status: dict[str, int] = {}
    for row in scans:
        key = str(row["status"])
        by_scan_status[key] = by_scan_status.get(key, 0) + 1
    by_severity = analysis_log.count_entries_by_severity(conn, analysis_id)
    return {
        "analysis_id": analysis_id,
        "binary_id": analysis["binary_id"],
        "status": analysis["status"],
        "engine": analysis["engine"],
        "created_at": analysis["created_at"],
        "finished_at": analysis["finished_at"],
        "terminal": str(analysis["status"]) in TERMINAL_STATUSES,
        "scans": len(scans),
        "scans_by_status": by_scan_status,
        "logs": analysis_log.count_entries(conn, analysis_id),
        "logs_by_severity": by_severity,
    }


# ── Imported functions ─────────────────────────────────────────────

# ``functions.name_source`` the rebrew importer labels an import stub with
# (``cli.THUNK_NAME_SOURCE``, which reads this constant).
IMPORTED_NAME_SOURCE = "import"

# Imported rows one read returns when the caller names no limit, and the cap.
DEFAULT_IMPORTED_LIMIT = 200
MAX_IMPORTED_LIMIT = 1000

# Callers one imported function carries in its answer, with the true total
# beside them.
IMPORTED_CALLER_LIMIT = 20


def _import_callers(
    conn: sqlite3.Connection, analysis_id: int, *, function_id: int, name: str
) -> tuple[list[dict[str, Any]], int]:
    """A bounded caller list for one import stub, and its true count.

    reportal stores no call graph, so a caller is a function of the same
    analysis whose stored decompilation carries the stub's name.  A stub with no
    name has no callers rather than every function.
    """
    if not name:
        return [], 0
    where = (
        "f.analysis_id = ? AND f.id != ? AND EXISTS (SELECT 1 FROM decompilations d"
        " WHERE d.function_id = f.id AND d.code LIKE ? ESCAPE '\\')"
    )
    params: tuple[Any, ...] = (analysis_id, function_id, f"%{_escape_like(name)}%")
    count = int(
        conn.execute(f"SELECT COUNT(*) AS n FROM functions f WHERE {where}", params).fetchone()["n"]
    )
    rows = _rows(
        conn.execute(
            f"SELECT f.id, f.va, f.name FROM functions f WHERE {where}"
            " ORDER BY f.va ASC, f.id ASC LIMIT ?",
            (*params, IMPORTED_CALLER_LIMIT),
        )
    )
    return rows, count


def imported_functions(
    conn: sqlite3.Connection, analysis_id: int, *, limit: int = DEFAULT_IMPORTED_LIMIT
) -> dict[str, Any] | None:
    """The import stubs of one analysis, each with the functions that mention it.

    ``name_source`` is :data:`IMPORTED_NAME_SOURCE` for a stub the importer
    created.  The callers are derived from the text reportal stores, not from an
    engine-reported call graph, and the payload says so (``caller_method``)
    rather than passing a text match off as an edge.  An analysis with no stubs
    answers an empty list; an unknown id is ``None``.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return None
    bounded = max(1, min(int(limit), MAX_IMPORTED_LIMIT))
    rows = _rows(
        conn.execute(
            "SELECT * FROM functions WHERE analysis_id = ? AND name_source = ?"
            " ORDER BY va ASC, id ASC LIMIT ?",
            (analysis_id, IMPORTED_NAME_SOURCE, bounded),
        )
    )
    total = int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM functions WHERE analysis_id = ? AND name_source = ?",
            (analysis_id, IMPORTED_NAME_SOURCE),
        ).fetchone()["n"]
    )
    functions: list[dict[str, Any]] = []
    for row in rows:
        callers, caller_count = _import_callers(
            conn, analysis_id, function_id=int(row["id"]), name=str(row["name"])
        )
        entry = dict(row)
        entry["callers"] = callers
        entry["caller_count"] = caller_count
        functions.append(entry)
    return {
        "analysis_id": analysis_id,
        "binary_id": int(analysis["binary_id"]),
        "functions": functions,
        "count": len(functions),
        "total": total,
        "caller_method": "decompilation-text",
        "caller_limit": IMPORTED_CALLER_LIMIT,
    }


def update_analysis(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    engine: str | None = None,
    model: str | None = None,
) -> dict[str, Any] | None:
    """Set the engine label or the model of one analysis; None for an unknown id.

    The engine label is what a reader uses to tell two analyses of one binary
    apart, and the model is which registry entry last produced its stored
    artifacts (``models.py``).  Both are the fields the hosted update and
    upgrade routes carry that reportal has a local meaning for; ``status`` moves
    through :func:`update_analysis_status` and :func:`requeue_analysis`.
    """
    if get_analysis(conn, analysis_id) is None:
        return None
    if engine is not None:
        conn.execute("UPDATE analyses SET engine = ? WHERE id = ?", (engine, analysis_id))
        conn.commit()
    if model is not None:
        conn.execute("UPDATE analyses SET model = ? WHERE id = ?", (model, analysis_id))
        conn.commit()
    return get_analysis(conn, analysis_id)


def requeue_analysis(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """Put one analysis back to ``pending`` and clear its finish time.

    The hosted requeue re-runs the analysis. Locally this moves the lifecycle
    row through :func:`update_analysis_status`; the HTTP, CLI and MCP callers
    then queue a job for each stored scan that has a job kind.  Refuses while
    the analysis is ``processing`` so a live scan cannot finish into ``done``
    or ``failed`` after the requeue reset.  Raises :class:`ValueError` in that
    case; returns None for an unknown id.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return None
    if analysis["status"] == ANALYSIS_STATUS_PROCESSING:
        raise ValueError(
            f"analysis {analysis_id} is processing; wait for scans to finish before requeue"
        )
    update_analysis_status(conn, analysis_id, status=ANALYSIS_STATUS_PENDING)
    return get_analysis(conn, analysis_id)


def analysis_filter_values(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """The values the analysis filters can actually match, for the SPA controls.

    The platform and architecture filters read the effective binary `format`
    and `arch` (a hand-set override first), which are whatever the crawler
    derived unless the operator corrected them, so the control is built from
    the register rather than from a vocabulary written down twice.  A blank
    or NULL column is left out.
    """

    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}

    def distinct(column: str) -> list[str]:
        effective = (
            f"COALESCE(NULLIF(b.{column}_override, ''), b.{column})"
            if column in ("format", "arch") and f"{column}_override" in columns
            else f"b.{column}"
        )
        cur = conn.execute(
            f"SELECT DISTINCT {effective} AS value FROM binaries b"
            f" WHERE {effective} IS NOT NULL AND {effective} != '' ORDER BY {effective}"
        )
        return [str(row["value"]) for row in cur.fetchall()]

    return {"platforms": distinct("format"), "architectures": distinct("arch")}


def count_analyses(
    conn: sqlite3.Connection,
    *,
    binary_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> int:
    """How many analyses exist, optionally of one binary.

    A filtered listing reports this beside its rows so a reader can tell a
    filter that matched nothing from a project with no analyses at all.
    ``visible_to`` narrows to what the caller may see, like :func:`list_analyses`.
    """
    sql = "SELECT COUNT(*) AS total FROM analyses a JOIN binaries b ON a.binary_id = b.id"
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clauses.append(scope[0])
        params.extend(scope[1])
    if binary_id is not None:
        clauses.append("a.binary_id = ?")
        params.append(binary_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    row = conn.execute(sql, params).fetchone()
    return int(row["total"]) if row else 0


def _tags_for_binaries(conn: sqlite3.Connection, binary_ids: Sequence[int]) -> dict[int, list[str]]:
    """Tag names per binary id, name order, for a listing's tag column."""
    grouped: dict[int, list[str]] = {}
    if not binary_ids:
        return grouped
    placeholders = ", ".join("?" for _ in binary_ids)
    cursor = conn.execute(
        "SELECT bt.binary_id AS binary_id, t.name AS name FROM binary_tags bt"
        " JOIN tags t ON t.id = bt.tag_id"
        f" WHERE bt.binary_id IN ({placeholders}) ORDER BY t.name COLLATE NOCASE",
        list(binary_ids),
    )
    for row in cursor.fetchall():
        grouped.setdefault(int(row["binary_id"]), []).append(str(row["name"]))
    return grouped


def list_analyses(
    conn: sqlite3.Connection,
    *,
    binary_id: int | None = None,
    status: str | None = None,
    statuses: Sequence[str] = (),
    search: str | None = None,
    workspace: str | None = None,
    platform: str | None = None,
    arch: str | None = None,
    order: str = DEFAULT_ANALYSIS_ORDER,
    limit: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Analyses with their binary name, owner, visibility, size, format and tags.

    ``status`` is one of :data:`ANALYSIS_STATUSES`, ``workspace`` one of
    :data:`WORKSPACE_FILTERS` and ``order`` one of :data:`ANALYSIS_ORDERS`;
    either being unknown raises :class:`ValueError`.  ``search`` matches the
    binary name, the binary's SHA-256 (a prefix is enough, which is what an
    analyst has when they know the sample rather than its name) or the engine
    label, case-insensitively.  ``limit`` is bounded by
    :data:`MAX_ANALYSIS_LIMIT` and defaults to :data:`DEFAULT_ANALYSIS_LIMIT`.
    Tag names are the owning binary's, ordered by name.

    An analysis has no scope of its own: the scope is the owning binary's, which
    is the object reportal stores a team on, so each row carries that binary's
    ``visibility``, ``owner_team_id`` and ``owner_team_name``.  ``workspace``
    reads that scope as the hosted portal's three controls: ``personal`` is an
    object no team owns, ``team`` one a team does, and ``public`` one the whole
    workspace may see.  ``visible_to`` is the authenticated caller (None while
    auth is off); a non-admin caller sees only analyses of public binaries
    and its own teams', which is what `auth.visible_clause` expresses.
    """
    for value in (status, *statuses):
        if value is not None and value not in ANALYSIS_STATUSES:
            raise ValueError(f"unknown analysis status: {value}")
    if workspace is not None and workspace not in WORKSPACE_FILTERS:
        raise ValueError(f"unknown workspace filter: {workspace}")
    if order not in ANALYSIS_ORDERS:
        raise ValueError(f"unknown analysis order: {order}")
    bound = DEFAULT_ANALYSIS_LIMIT if limit is None else limit
    if bound < 1 or bound > MAX_ANALYSIS_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_ANALYSIS_LIMIT}")
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}
    if {"format_override", "arch_override"} <= columns:
        format_select = (
            "COALESCE(NULLIF(b.format_override, ''), b.format) AS binary_format,"
            " COALESCE(NULLIF(b.arch_override, ''), b.arch) AS binary_arch,"
            " b.format_override AS binary_format_override,"
            " b.arch_override AS binary_arch_override,"
        )
    else:
        format_select = (
            "b.format AS binary_format, b.arch AS binary_arch,"
            " '' AS binary_format_override, '' AS binary_arch_override,"
        )
    sql = (
        "SELECT a.*, b.name AS binary_name, b.size AS binary_size,"
        f" {format_select} b.sha256 AS binary_sha256,"
        " b.visibility AS visibility, b.owner_team_id AS owner_team_id,"
        " t.name AS owner_team_name FROM analyses a JOIN binaries b ON a.binary_id = b.id"
        " LEFT JOIN teams t ON t.id = b.owner_team_id"
    )
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clauses.append(scope[0])
        params.extend(scope[1])
    if binary_id is not None:
        clauses.append("a.binary_id = ?")
        params.append(binary_id)
    chosen = [value for value in (status, *statuses) if value is not None]
    if chosen:
        placeholders = ", ".join("?" for _ in chosen)
        clauses.append(f"a.status IN ({placeholders})")
        params.extend(chosen)
    overridden = {"format_override", "arch_override"} <= columns
    if platform is not None:
        clauses.append(
            "COALESCE(NULLIF(b.format_override, ''), b.format) = ?"
            if overridden
            else "b.format = ?"
        )
        params.append(platform)
    if arch is not None:
        clauses.append(
            "COALESCE(NULLIF(b.arch_override, ''), b.arch) = ?" if overridden else "b.arch = ?"
        )
        params.append(arch)
    if search:
        pattern = _escape_like(search)
        clauses.append(
            "(b.name LIKE ? ESCAPE '\\' OR a.engine LIKE ? ESCAPE '\\'"
            " OR b.sha256 LIKE ? ESCAPE '\\')"
        )
        params.extend((pattern, pattern, pattern))
    if workspace == WORKSPACE_PERSONAL:
        clauses.append("b.owner_team_id IS NULL")
    elif workspace == WORKSPACE_TEAM:
        clauses.append("b.owner_team_id IS NOT NULL")
    elif workspace == WORKSPACE_PUBLIC:
        clauses.append("b.visibility = ?")
        params.append("public")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += f" ORDER BY {_ANALYSIS_ORDER_SQL[order]} LIMIT ?"
    params.append(bound)
    rows = _rows(conn.execute(sql, params))
    tags = _tags_for_binaries(conn, [int(row["binary_id"]) for row in rows])
    for row in rows:
        row["tags"] = tags.get(int(row["binary_id"]), [])
    return rows


def get_analysis(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    cur = conn.execute(
        "SELECT a.*, b.name AS binary_name FROM analyses a"
        " JOIN binaries b ON a.binary_id = b.id WHERE a.id = ?",
        (analysis_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def delete_analysis(conn: sqlite3.Connection, analysis_id: int) -> bool:
    """Delete one analysis; False when the id is unknown.

    Every dependent row cascades with it: its functions (and their matches,
    history, decompilations and AI artifacts), its scans and its log entries.
    A caller that needs the delete revertible journals it first (see
    ``journal.journaled_analysis_delete``).
    """
    cur = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    return cur.rowcount > 0


def is_last_analysis_with_functions(conn: sqlite3.Connection, analysis_id: int) -> bool:
    """Whether deleting *analysis_id* would take a binary's whole function table.

    True for a binary's only analysis while it holds functions: the foreign-key
    cascade would remove them with it.  The intended path for that case is
    deleting the binary, so the callers refuse it.
    """
    analysis = get_analysis(conn, analysis_id)
    if analysis is None:
        return False
    binary_id = int(analysis["binary_id"])
    if count_analyses(conn, binary_id=binary_id) != 1:
        return False
    return count_functions(conn, analysis_id=analysis_id) > 0


def update_analysis_status(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    status: str,
    log: str | None = None,
    finished_at: str | None = None,
) -> bool:
    """Set an analysis status (and optionally log/finish time); False if unknown.

    *status* must be one of :data:`ANALYSIS_STATUSES`.  ``finished_at`` is
    stamped automatically when *status* is terminal and the caller supplied no
    explicit timestamp, and cleared when *status* is non-terminal unless the
    caller passed one: a reopen (``begin_scan``, a move back to ``pending``)
    must not keep the previous close time beside a live status.  A status that
    differs from the stored one appends a log entry, so the log carries every
    transition and not only the last.  The status write and that log row share
    one commit, so a crash cannot leave a transition without its entry.
    """
    if status not in ANALYSIS_STATUSES:
        raise ValueError(f"unknown analysis status: {status}")
    row = conn.execute("SELECT status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        return False
    previous = str(row["status"])
    clear_finished = False
    if finished_at is None and status in TERMINAL_STATUSES:
        finished_at = now()
    elif finished_at is None and status not in TERMINAL_STATUSES:
        clear_finished = True
    assignments = ["status = ?"]
    params: list[Any] = [status]
    if log is not None:
        assignments.append("log = ?")
        params.append(log)
    if finished_at is not None:
        assignments.append("finished_at = ?")
        params.append(finished_at)
    elif clear_finished:
        assignments.append("finished_at = NULL")
    params.append(analysis_id)
    # Ensure the log table exists before the status write: ``executescript``
    # commits, and must not cut the status UPDATE off from its log INSERT.
    if status != previous:
        analysis_log.ensure_schema(conn)
    cur = conn.execute(f"UPDATE analyses SET {', '.join(assignments)} WHERE id = ?", params)
    if status != previous:
        severity = analysis_log.SEVERITY_INFO
        if status == ANALYSIS_STATUS_FAILED:
            severity = analysis_log.SEVERITY_ERROR
        elif status == ANALYSIS_STATUS_CANCELLED:
            severity = analysis_log.SEVERITY_WARN
        analysis_log.append_entry(
            conn,
            analysis_id,
            severity=severity,
            message=f"status changed to {status} (was {previous})",
            commit=False,
        )
    conn.commit()
    return cur.rowcount > 0


# ── Analysis scan lifecycle ────────────────────────────────────────


def begin_scan(conn: sqlite3.Connection, analysis_id: int, kind: str) -> None:
    """Record that a scan of *kind* started and move the analysis to `processing`."""
    analysis_log.append_entry(conn, analysis_id, message=f"{kind} scan started")
    update_analysis_status(conn, analysis_id, status=ANALYSIS_STATUS_PROCESSING)


def fail_scan(conn: sqlite3.Connection, analysis_id: int, kind: str, message: str = "") -> None:
    """Record that a scan of *kind* failed and move the analysis to `failed`."""
    detail = f": {message}" if message else ""
    analysis_log.append_entry(
        conn,
        analysis_id,
        severity=analysis_log.SEVERITY_ERROR,
        message=f"{kind} scan failed{detail}",
    )
    update_analysis_status(conn, analysis_id, status=ANALYSIS_STATUS_FAILED)


def _scan_analysis(
    conn: sqlite3.Connection, binary_id: int, *, ensure: bool, engine: str
) -> int | None:
    """The analysis a scan of *binary_id* can hang off, or None.

    A binary that has no row has no analysis to blame a failure on, and an
    analysis cannot exist without one (the foreign key forbids it), so the
    resolution stops there instead of creating a row the schema would reject.
    """
    if get_binary(conn, binary_id) is None:
        return None
    if not ensure:
        return latest_analysis_for_binary(conn, binary_id)
    return ensure_analysis_for_binary(conn, binary_id, engine=engine)


@contextlib.contextmanager
def scan_span(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    kind: str,
    engine: str = SCAN_ENGINE,
    ensure_analysis: bool = True,
) -> Iterator[int | None]:
    """Log a scan's start, and its failure, around the work it wraps.

    *ensure_analysis* resolves the binary's analysis first, creating one when
    it has none; the caller that already journals the analysis row keeps its
    own bookkeeping and passes false, which logs a start only when an analysis
    already exists.  A failure always leaves a row to blame: when there is no
    analysis yet, one is created for the failure entry.  A binary that has no
    row at all gets neither, since the log hangs off an analysis that cannot
    exist for it.  The exception is re-raised unchanged.
    """
    analysis_id = _scan_analysis(conn, binary_id, ensure=ensure_analysis, engine=engine)
    if analysis_id is not None:
        begin_scan(conn, analysis_id, kind)
    try:
        yield analysis_id
    except Exception as exc:
        target = analysis_id
        if target is None:
            target = _scan_analysis(conn, binary_id, ensure=True, engine=engine)
        if target is not None:
            fail_scan(conn, target, kind, str(exc))
        raise


# ── Functions ──────────────────────────────────────────────────────


def add_function(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    va: int,
    name: str = "",
    size: int = 0,
    status: str = "unknown",
    name_source: str = "",
    confidence: float = 0.0,
    source_path: str = "",
) -> int:
    """Insert a function row; returns its id."""
    cur = conn.execute(
        "INSERT INTO functions"
        " (analysis_id, va, name, size, status, name_source, confidence, source_path)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (analysis_id, va, name, size, status, name_source, confidence, source_path),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def upsert_function(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    va: int,
    name: str = "",
    size: int = 0,
    status: str = "unknown",
    name_source: str = "",
    confidence: float = 0.0,
    source_path: str = "",
) -> tuple[int, bool]:
    """Insert or refresh the function at *va* in *analysis_id*.

    Returns ``(id, created)``.  Re-importing a workspace refreshes existing
    rows instead of duplicating them, which is what makes ``import-rebrew``
    idempotent.  A size change widens or shrinks the engine's disassembly
    window, so the cached listing for that function is dropped together with
    any stored decompilation and AI artifacts derived from the old extent; a
    refresh that keeps the same size leaves those alone.
    """
    row = conn.execute(
        "SELECT id, size FROM functions WHERE analysis_id = ? AND va = ?", (analysis_id, va)
    ).fetchone()
    if row is not None:
        function_id = int(row["id"])
        previous_size = int(row["size"])
        conn.execute(
            "UPDATE functions SET name = ?, size = ?, status = ?, name_source = ?,"
            " confidence = ?, source_path = ? WHERE id = ?",
            (name, size, status, name_source, confidence, source_path, function_id),
        )
        conn.commit()
        if previous_size != size:
            clear_disasm(conn, function_id)
            clear_decompilation(conn, function_id)
            conn.execute("DELETE FROM ai_artifacts WHERE function_id = ?", (function_id,))
            conn.commit()
        return function_id, False
    return (
        add_function(
            conn,
            analysis_id=analysis_id,
            va=va,
            name=name,
            size=size,
            status=status,
            name_source=name_source,
            confidence=confidence,
            source_path=source_path,
        ),
        True,
    )


def add_function_if_absent(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    va: int,
    name: str = "",
    size: int = 0,
    status: str = "unknown",
    name_source: str = "",
    confidence: float = 0.0,
    source_path: str = "",
) -> int | None:
    """Insert a function row unless *va* is taken in *analysis_id*; None when it is.

    Unlike :func:`upsert_function` this never replaces an existing row, so a
    weaker source (an import stub) cannot overwrite a stronger one (a
    coverage-db function) at the same address.
    """
    row = conn.execute(
        "SELECT id FROM functions WHERE analysis_id = ? AND va = ?", (analysis_id, va)
    ).fetchone()
    if row is not None:
        return None
    return add_function(
        conn,
        analysis_id=analysis_id,
        va=va,
        name=name,
        size=size,
        status=status,
        name_source=name_source,
        confidence=confidence,
        source_path=source_path,
    )


# Function columns `list_functions` sorts by, and the value that means "no
# filter" for the stored match state.  The column names come from this table,
# never from the request, so a sort key cannot splice SQL.
FUNCTION_SORT_COLUMNS: dict[str, str] = {
    "va": "f.va",
    "size": "f.size",
    "name": "f.name",
    "status": "f.status",
}
DEFAULT_FUNCTION_SORT = "va"
FUNCTION_ORDERS: tuple[str, ...] = ("asc", "desc")
DEFAULT_FUNCTION_ORDER = "asc"

# String-row sort vocabulary for the strings route and `reportal strings`.
# Both order a normalized row list by the text (`value`) or its length, in the
# direction `FUNCTION_ORDERS` names.
STRING_SORTS: tuple[str, ...] = ("value", "length")
DEFAULT_STRING_SORT = "value"


def normalize_string_entries(payload: Any) -> list[dict[str, Any]]:
    """Normalize an engine strings payload to ``{va, section, kind, size, text}`` rows.

    ``rebrew strings`` answers objects with a VA, section, kind and size; an
    older payload (and a test double) answers bare text.  Both become the same
    row, and a field the engine did not report stays null rather than being
    filled in.
    """
    raw = payload.get("strings") if isinstance(payload, Mapping) else None
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        text = str(entry.get("text") or "") if isinstance(entry, Mapping) else str(entry)
        va: int | None = None
        section: str | None = None
        kind: str | None = None
        size = len(text)
        if isinstance(entry, Mapping):
            address = entry.get("va")
            if isinstance(address, int) and not isinstance(address, bool):
                va = address
            elif address is not None:
                try:
                    va = int(str(address), 0)
                except ValueError:
                    va = None
            if entry.get("section"):
                section = str(entry["section"])
            if entry.get("kind"):
                kind = str(entry["kind"])
            declared = entry.get("size")
            if isinstance(declared, int) and not isinstance(declared, bool):
                size = declared
        rows.append({"va": va, "section": section, "kind": kind, "size": size, "text": text})
    return rows


def sort_string_entries(
    entries: Sequence[Mapping[str, Any]], *, sort: str, order: str
) -> list[dict[str, Any]]:
    """Order string rows by value or length, ties broken by text then address.

    A tie is deterministic: equal lengths fall back to the text, then to the
    address (an absent one first), so two runs over the same payload answer the
    same order.  An unknown *sort* or *order* raises :class:`ValueError`.
    """
    if sort not in STRING_SORTS:
        raise ValueError(f"unknown string sort: {sort}")
    if order not in FUNCTION_ORDERS:
        raise ValueError(f"unknown string order: {order}")
    rows = [dict(entry) for entry in entries]

    def address(row: Mapping[str, Any]) -> int:
        value = row.get("va")
        return value if isinstance(value, int) and not isinstance(value, bool) else -1

    if sort == "length":
        return sorted(
            rows,
            key=lambda row: (len(row["text"]), row["text"], address(row)),
            reverse=order == "desc",
        )
    return sorted(rows, key=lambda row: (row["text"], address(row)), reverse=order == "desc")


# Stored match-state filter values: `matched` is a function the stored
# `matches` table names as the source of a match, `unmatched` one it does not.
FUNCTION_MATCH_MATCHED = "matched"
FUNCTION_MATCH_UNMATCHED = "unmatched"
FUNCTION_MATCH_VALUES: tuple[str, ...] = (FUNCTION_MATCH_MATCHED, FUNCTION_MATCH_UNMATCHED)

# The largest page the function listing route will serve.  The in-process
# callers (auto mode, benchmarks, exports) pass no limit and still read every
# row; the bound exists for the HTTP path, where an unpaged binary sent its
# whole function table on every poll.
MAX_FUNCTION_LIMIT = 1000


def _function_where(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None,
    binary_id: int | None,
    binary_ids: Sequence[int],
    min_size: int | None,
    max_size: int | None,
    string: str | None,
    strings: Sequence[str],
    regex: bool,
    match: str | None,
    name: str | None,
    va: int | None,
) -> tuple[str, list[Any]]:
    """The shared ``WHERE`` of the function listing and its count.

    Returned as the clause text (empty when nothing filters) plus its
    parameters, so :func:`list_functions` and :func:`count_matching_functions`
    cannot drift: a page's match total has to count the same predicate the page
    was cut from.  *binary_ids* keeps functions of any of those binaries; an
    empty sequence adds no clause.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if analysis_id is not None:
        clauses.append("f.analysis_id = ?")
        params.append(analysis_id)
    if binary_id is not None:
        clauses.append("a.binary_id = ?")
        params.append(binary_id)
    if binary_ids:
        ids = [int(value) for value in binary_ids]
        placeholders = ", ".join("?" for _ in ids)
        clauses.append(f"a.binary_id IN ({placeholders})")
        params.extend(ids)
    if min_size is not None:
        clauses.append("f.size >= ?")
        params.append(min_size)
    if max_size is not None:
        clauses.append("f.size <= ?")
        params.append(max_size)
    needles = [value for value in (string, *strings) if value]
    if needles:
        if regex:
            for value in needles:
                compile_regex(value)
            register_regexp(conn)
        alternatives: list[str] = []
        for matcher in (_Match(value, regex=regex) for value in needles):
            code_sql, code_param = matcher.clause("d.code")
            alternatives.append(code_sql)
            params.append(code_param)
        clauses.append(
            "EXISTS (SELECT 1 FROM decompilations d WHERE d.function_id = f.id"
            " AND (" + " OR ".join(alternatives) + "))"
        )
    if match is not None:
        exists = "EXISTS (SELECT 1 FROM matches m WHERE m.function_id = f.id)"
        clauses.append(exists if match == FUNCTION_MATCH_MATCHED else f"NOT {exists}")
    if name:
        clauses.append("f.name LIKE ? ESCAPE '\\'")
        params.append(_escape_like(name))
    if va is not None:
        clauses.append("f.va = ?")
        params.append(va)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def count_matching_functions(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None = None,
    binary_id: int | None = None,
    binary_ids: Sequence[int] = (),
    min_size: int | None = None,
    max_size: int | None = None,
    string: str | None = None,
    strings: Sequence[str] = (),
    regex: bool = False,
    match: str | None = None,
    name: str | None = None,
    va: int | None = None,
) -> int:
    """How many functions the same filters :func:`list_functions` takes keep.

    This is what a paged listing reports as its match count: counting in
    SQLite is what lets the page be a ``LIMIT`` instead of a whole-table read.
    """
    if match is not None and match not in FUNCTION_MATCH_VALUES:
        raise ValueError(f"unknown match filter: {match}")
    where, params = _function_where(
        conn,
        analysis_id=analysis_id,
        binary_id=binary_id,
        binary_ids=binary_ids,
        min_size=min_size,
        max_size=max_size,
        string=string,
        strings=strings,
        regex=regex,
        match=match,
        name=name,
        va=va,
    )
    sql = (
        "SELECT COUNT(*) AS total FROM functions f JOIN analyses a ON f.analysis_id = a.id" + where
    )
    row = conn.execute(sql, params).fetchone()
    return int(row["total"]) if row is not None else 0


def list_functions(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None = None,
    binary_id: int | None = None,
    binary_ids: Sequence[int] = (),
    min_size: int | None = None,
    max_size: int | None = None,
    string: str | None = None,
    strings: Sequence[str] = (),
    regex: bool = False,
    match: str | None = None,
    name: str | None = None,
    va: int | None = None,
    sort: str = DEFAULT_FUNCTION_SORT,
    order: str = DEFAULT_FUNCTION_ORDER,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Functions (optionally scoped and filtered), with analysis/binary ids.

    ``sort`` names one of :data:`FUNCTION_SORT_COLUMNS` and ``order`` one of
    :data:`FUNCTION_ORDERS`; either being unknown raises :class:`ValueError`.
    Ties break on ``f.id``, so a listing is deterministic.  ``min_size`` and
    ``max_size`` are inclusive byte bounds, ``name`` is a case-insensitive
    substring of the function's name (an escaped ``LIKE``, so a wildcard in the
    needle stays literal), ``va`` is one exact address and ``string``/``strings``
    match the function's stored decompilation text (a literal the reversed source
    carries; a function with none never matches) and ``match`` is one of
    :data:`FUNCTION_MATCH_VALUES`.  ``binary_ids`` keeps functions of any of
    those binaries in one round trip; an empty sequence adds no binary filter.

    Several needles are combined as any-of, so a filter listing three strings
    keeps a function that carries any one of them.  ``regex=True`` treats every
    needle as a regular expression through the same bounded, cached compiler
    :func:`compile_regex` provides, and raises ``SearchError("invalid regex",
    ...)`` for one that does not compile.

    ``limit`` bounds the page and ``offset`` skips that many rows of it; None
    (the default) returns every match, which is what the in-process callers
    reading a whole binary want.  A limit above :data:`MAX_FUNCTION_LIMIT` or
    below 1, or a negative offset, raises :class:`ValueError`.
    """
    if sort not in FUNCTION_SORT_COLUMNS:
        raise ValueError(f"unknown function sort: {sort}")
    if order not in FUNCTION_ORDERS:
        raise ValueError(f"unknown function order: {order}")
    if match is not None and match not in FUNCTION_MATCH_VALUES:
        raise ValueError(f"unknown match filter: {match}")
    if limit is not None and not 1 <= limit <= MAX_FUNCTION_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_FUNCTION_LIMIT}")
    if offset < 0:
        raise ValueError("offset must not be negative")
    where, params = _function_where(
        conn,
        analysis_id=analysis_id,
        binary_id=binary_id,
        binary_ids=binary_ids,
        min_size=min_size,
        max_size=max_size,
        string=string,
        strings=strings,
        regex=regex,
        match=match,
        name=name,
        va=va,
    )
    sql = (
        "SELECT f.*, a.binary_id AS binary_id FROM functions f"
        " JOIN analyses a ON f.analysis_id = a.id" + where
    )
    direction = "ASC" if order == DEFAULT_FUNCTION_ORDER else "DESC"
    sql += f" ORDER BY {FUNCTION_SORT_COLUMNS[sort]} {direction}, f.id ASC"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params += [limit, offset]
    elif offset:
        sql += " LIMIT -1 OFFSET ?"
        params.append(offset)
    return _rows(conn.execute(sql, params))


def count_functions(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None = None,
    binary_id: int | None = None,
) -> int:
    """How many functions exist in the scope, ignoring every filter.

    A filtered listing reports this beside its rows so a reader can tell a
    filter that matched nothing from a binary with no functions at all.
    """
    sql = "SELECT COUNT(*) AS total FROM functions f JOIN analyses a ON f.analysis_id = a.id"
    clauses: list[str] = []
    params: list[Any] = []
    if analysis_id is not None:
        clauses.append("f.analysis_id = ?")
        params.append(analysis_id)
    if binary_id is not None:
        clauses.append("a.binary_id = ?")
        params.append(binary_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    row = conn.execute(sql, params).fetchone()
    return int(row["total"]) if row else 0


def function_ids(
    conn: sqlite3.Connection,
    *,
    analysis_id: int | None = None,
    binary_id: int | None = None,
) -> set[int]:
    """The function ids in the scope, without loading full function rows.

    Membership checks (signature copy, batch writes) need the id set, not the
    joined listing :func:`list_functions` builds for the SPA.
    """
    sql = "SELECT f.id AS id FROM functions f JOIN analyses a ON f.analysis_id = a.id"
    clauses: list[str] = []
    params: list[Any] = []
    if analysis_id is not None:
        clauses.append("f.analysis_id = ?")
        params.append(analysis_id)
    if binary_id is not None:
        clauses.append("a.binary_id = ?")
        params.append(binary_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return {int(row["id"]) for row in conn.execute(sql, params)}


def _binary_function_rows(
    conn: sqlite3.Connection,
    binary_id: int,
    limit: int | None,
    *,
    exclude_statuses: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Functions of *binary_id*, smallest first then VA, minus *exclude_statuses*."""
    sql = (
        "SELECT f.*, a.binary_id AS binary_id FROM functions f"
        " JOIN analyses a ON f.analysis_id = a.id"
        " WHERE a.binary_id = ?"
    )
    params: list[Any] = [binary_id]
    if exclude_statuses:
        placeholders = ", ".join("?" for _ in exclude_statuses)
        sql += f" AND COALESCE(f.status, '') NOT IN ({placeholders})"
        params.extend(exclude_statuses)
    sql += " ORDER BY f.size ASC, f.va ASC, f.id ASC"
    if limit is not None:
        if not 1 <= limit <= MAX_FUNCTION_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_FUNCTION_LIMIT}")
        sql += " LIMIT ?"
        params.append(limit)
    return _rows(conn.execute(sql, params))


def list_outstanding_functions(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Functions of *binary_id* whose status is not yet matched, smallest first.

    Auto mode's selection path used to read every function then drop the matched
    ones in Python; filtering and ordering in SQLite keeps a mostly-matched
    binary from shipping its whole table into the planner.
    """
    return _binary_function_rows(conn, binary_id, limit, exclude_statuses=sorted(MATCHED_STATUSES))


def list_binary_functions(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Every function of *binary_id*, smallest first then VA.

    A goal-directed auto run patches the function a goal names, which may
    already carry a matching status, so it plans from this selection rather
    than :func:`list_outstanding_functions`.
    """
    return _binary_function_rows(conn, binary_id, limit)


def function_rollup(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """A binary's function table as the three numbers a summary actually shows.

    The dashboard used to read every function row per binary to derive exactly
    this: the total, how many carry a matched status, and the per-status
    breakdown.  Counting in SQLite answers the same question without moving the
    rows, which is what keeps a 5,000-function binary off the landing path.
    ``by_status`` is ordered by descending count, then by status, so the chips
    render in a stable order.
    """
    rows = conn.execute(
        "SELECT f.status AS status, COUNT(*) AS n FROM functions f"
        " JOIN analyses a ON f.analysis_id = a.id WHERE a.binary_id = ?"
        " GROUP BY f.status ORDER BY n DESC, f.status ASC",
        (binary_id,),
    ).fetchall()
    by_status = {str(row["status"] or ""): int(row["n"]) for row in rows}
    return {
        "binary_id": binary_id,
        "total": sum(by_status.values()),
        "matched": sum(count for status, count in by_status.items() if status in MATCHED_STATUSES),
        "by_status": by_status,
    }


def get_function(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    cur = conn.execute(
        "SELECT f.*, a.binary_id AS binary_id FROM functions f"
        " JOIN analyses a ON f.analysis_id = a.id WHERE f.id = ?",
        (function_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def functions_by_ids(
    conn: sqlite3.Connection, function_ids: Sequence[int]
) -> dict[int, dict[str, Any]]:
    """The functions named by *function_ids*, keyed by id.

    One round trip for a batch read; an unknown id is simply absent from the
    map, which is what the batch surfaces report as not found.
    """
    if not function_ids:
        return {}
    ids = [int(function_id) for function_id in function_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        "SELECT f.*, a.binary_id AS binary_id FROM functions f"
        f" JOIN analyses a ON f.analysis_id = a.id WHERE f.id IN ({placeholders})",
        ids,
    )
    return {int(row["id"]): dict(row) for row in cur.fetchall()}


# ── Matches ────────────────────────────────────────────────────────


def record_match(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    candidate_function_id: int,
    similarity: float,
    confidence: float,
    settings: Mapping[str, Any] | None = None,
    source_arch: str = "",
    candidate_arch: str = "",
    commit: bool = True,
) -> int:
    """Record a similarity edge between two functions; returns its id.

    Re-recording the same ordered pair refreshes the scores instead of
    inserting a duplicate row (the pair is UNIQUE).  *settings* is the match
    run's scope, stored with the row so a later reader can tell which run
    produced it; None records no settings, which is what an edge written
    outside a match run carries.  *source_arch* and *candidate_arch* are the
    ISA tokens of the two binaries at record time, so a later reader can tell
    a cross-architecture pair from a same-ISA one.  Pass ``commit=False`` when
    the caller will commit a source function's clear and its edges together.
    """
    conn.execute(
        "INSERT INTO matches (function_id, candidate_function_id, similarity,"
        " confidence, settings_json, source_arch, candidate_arch, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(function_id, candidate_function_id) DO UPDATE SET"
        " similarity = excluded.similarity, confidence = excluded.confidence,"
        " settings_json = excluded.settings_json,"
        " source_arch = excluded.source_arch,"
        " candidate_arch = excluded.candidate_arch",
        (
            function_id,
            candidate_function_id,
            similarity,
            confidence,
            json.dumps(dict(settings)) if settings is not None else "",
            source_arch,
            candidate_arch,
            now(),
        ),
    )
    if commit:
        conn.commit()
    row = conn.execute(
        "SELECT id FROM matches WHERE function_id = ? AND candidate_function_id = ?",
        (function_id, candidate_function_id),
    ).fetchone()
    return int(row["id"]) if row else 0


def _match_row(row: sqlite3.Row) -> dict[str, Any]:
    """One match row with its stored run settings parsed from JSON."""
    match = dict(row)
    raw = str(match.pop("settings_json", "") or "")
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        match["settings"] = parsed if isinstance(parsed, dict) else None
    else:
        match["settings"] = None
    return match


def list_matches(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """Matches for *function_id*, best similarity first, with candidate info.

    Each row carries the run settings it was recorded under as ``settings``,
    or None for an edge written outside a match run.
    """
    return list_matches_for_functions(conn, [function_id]).get(int(function_id), [])


def list_matches_for_functions(
    conn: sqlite3.Connection, function_ids: Sequence[int]
) -> dict[int, list[dict[str, Any]]]:
    """Matches for many source functions in one query, best similarity first.

    Returns a map from source function id to its match rows (the same shape
    :func:`list_matches` returns).  An id with no matches is absent; callers
    that need an empty list for every requested id fill that themselves.
    """
    if not function_ids:
        return {}
    ids = [int(function_id) for function_id in function_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        f"""
        SELECT m.*, cf.va AS candidate_va, cf.name AS candidate_name,
               cf.status AS candidate_status
        FROM matches m
        JOIN functions cf ON m.candidate_function_id = cf.id
        WHERE m.function_id IN ({placeholders})
        ORDER BY m.function_id ASC, m.similarity DESC, m.id
        """,
        ids,
    )
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in cur.fetchall():
        grouped.setdefault(int(row["function_id"]), []).append(_match_row(row))
    return grouped


def list_matches_for_binary(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Every match whose source is a function of *binary_id*, best similarity first.

    Each row carries the source function's id, name, VA and name source beside
    the candidate columns :func:`list_matches` already reports, plus the
    candidate function's owning binary, so a binary-wide reader does not walk
    the functions table and query matches once per row.
    """
    cur = conn.execute(
        """
        SELECT m.*, cf.va AS candidate_va, cf.name AS candidate_name,
               cf.status AS candidate_status,
               sf.id AS source_function_id, sf.name AS source_name, sf.va AS source_va,
               sf.name_source AS source_name_source,
               cb.id AS candidate_binary_id, cb.name AS candidate_binary_name
        FROM matches m
        JOIN functions sf ON m.function_id = sf.id
        JOIN analyses a ON a.id = sf.analysis_id
        JOIN functions cf ON m.candidate_function_id = cf.id
        JOIN analyses ca ON ca.id = cf.analysis_id
        JOIN binaries cb ON cb.id = ca.binary_id
        WHERE a.binary_id = ?
        ORDER BY m.similarity DESC, m.id
        """,
        (binary_id,),
    )
    return [_match_row(row) for row in cur.fetchall()]


def match_counts_for_binary(conn: sqlite3.Connection, binary_id: int) -> dict[int, int]:
    """How many recorded matches each function of *binary_id* has, keyed by id.

    A function with no matches is absent, so a caller that only needs the count
    never materializes the match rows themselves.
    """
    cur = conn.execute(
        """
        SELECT m.function_id AS function_id, COUNT(*) AS n
        FROM matches m
        JOIN functions f ON m.function_id = f.id
        JOIN analyses a ON a.id = f.analysis_id
        WHERE a.binary_id = ?
        GROUP BY m.function_id
        """,
        (binary_id,),
    )
    return {int(row["function_id"]): int(row["n"]) for row in cur.fetchall()}


def has_match(conn: sqlite3.Connection, function_id: int, candidate_function_id: int) -> bool:
    """True when a recorded match row links the two functions in that order."""
    row = conn.execute(
        "SELECT 1 FROM matches WHERE function_id = ? AND candidate_function_id = ?",
        (function_id, candidate_function_id),
    ).fetchone()
    return row is not None


def clear_matches_for(conn: sqlite3.Connection, function_id: int, *, commit: bool = True) -> None:
    """Delete every match row whose source is *function_id*.

    Matching recomputes a function's edges from scratch, so the previous run's
    rows must go first; otherwise a candidate that fell below the floor would
    survive with a stale score.  Pass ``commit=False`` when the caller will
    commit the clear with the replacement edges in one transaction.
    """
    conn.execute("DELETE FROM matches WHERE function_id = ?", (function_id,))
    if commit:
        conn.commit()


# ── Disassembly cache ──────────────────────────────────────────────

# The only listing format the cache holds: `disasm_cache` is one text per
# function, and the hex view is a rendering of the same bytes rather than
# something worth storing.  The route, the MCP tool and the CLI all read the
# cache under the same rule, so it lives here rather than once per surface.
CACHEABLE_DISASM_FORMAT = "nasm"


def _disasm_identity(conn: sqlite3.Connection, function_id: int) -> tuple[int, str] | None:
    """The live ``(extent_size, project_dir)`` of *function_id*, or None if gone.

    ``project_dir`` is empty when the binary has no rebrew context yet; a
    listing written against that empty identity is still validated on read.
    """
    row = conn.execute(
        "SELECT f.size AS size, r.project_dir AS project_dir"
        " FROM functions f"
        " JOIN analyses a ON a.id = f.analysis_id"
        " LEFT JOIN rebrew_contexts r ON r.binary_id = a.binary_id"
        " WHERE f.id = ?",
        (function_id,),
    ).fetchone()
    if row is None:
        return None
    live_dir = "" if row["project_dir"] is None else str(row["project_dir"])
    return int(row["size"]), live_dir


def set_disasm(
    conn: sqlite3.Connection,
    function_id: int,
    text: str,
    *,
    extent_size: int | None = None,
    project_dir: str | None = None,
) -> bool:
    """Store the assembly listing of *function_id*, replacing any earlier one.

    *extent_size* and *project_dir* are the engine inputs the listing was
    produced from.  When given, the write is refused if the live function or
    rebrew context has moved on, so a concurrent invalidation cannot be
    overwritten by a stale compute.  When omitted, the live values are
    recorded (test seeding and callers that already hold a consistent
    snapshot).  Returns False when the function is gone or the write was
    refused.

    The identity check and the upsert share ``BEGIN IMMEDIATE``: without the
    write lock, a clear that lands between the read and the insert would leave
    a stale listing until a later :func:`get_disasm` dropped it.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        live = _disasm_identity(conn, function_id)
        if live is None:
            conn.rollback()
            return False
        live_size, live_dir = live
        if extent_size is not None and extent_size != live_size:
            conn.rollback()
            return False
        if project_dir is not None and project_dir != live_dir:
            conn.rollback()
            return False
        recorded_size = live_size if extent_size is None else extent_size
        recorded_dir = live_dir if project_dir is None else project_dir
        conn.execute(
            "INSERT INTO disasm_cache"
            " (function_id, text, extent_size, project_dir, created_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(function_id) DO UPDATE SET text = excluded.text,"
            " extent_size = excluded.extent_size, project_dir = excluded.project_dir,"
            " created_at = excluded.created_at",
            (function_id, text, recorded_size, recorded_dir, now()),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return True


def get_disasm(conn: sqlite3.Connection, function_id: int) -> str | None:
    """Return the cached assembly listing of *function_id*, or None.

    A row whose recorded extent or project directory no longer matches the
    live function is dropped rather than served: the write paths clear on
    those changes, and this read-side check closes the cache-aside race where
    a stale compute lands after the clear.
    """
    row = conn.execute(
        "SELECT d.text AS text, d.extent_size AS extent_size,"
        " d.project_dir AS project_dir, f.size AS size,"
        " r.project_dir AS live_dir"
        " FROM disasm_cache d"
        " JOIN functions f ON f.id = d.function_id"
        " JOIN analyses a ON a.id = f.analysis_id"
        " LEFT JOIN rebrew_contexts r ON r.binary_id = a.binary_id"
        " WHERE d.function_id = ?",
        (function_id,),
    ).fetchone()
    if row is None:
        return None
    live_dir = "" if row["live_dir"] is None else str(row["live_dir"])
    if int(row["extent_size"]) != int(row["size"]) or str(row["project_dir"]) != live_dir:
        clear_disasm(conn, function_id)
        return None
    return str(row["text"])


def clear_disasm(conn: sqlite3.Connection, function_id: int) -> bool:
    """Drop the cached listing of *function_id*; False when there was none."""
    cur = conn.execute("DELETE FROM disasm_cache WHERE function_id = ?", (function_id,))
    conn.commit()
    return cur.rowcount > 0


# In-flight disassembly fills keyed by function id.  A cache miss under
# concurrency must not fan every waiter into its own engine call: the first
# computes and stores, the rest wait and re-read.
_DISASM_GATES: dict[int, threading.Event] = {}
_DISASM_GATES_LOCK = threading.Lock()


def get_or_compute_disasm(
    conn: sqlite3.Connection,
    function_id: int,
    compute: Callable[[], str],
    *,
    extent_size: int,
    project_dir: str,
) -> tuple[str, bool]:
    """Return ``(listing, filled)`` under singleflight.

    *filled* is True when this caller ran *compute* and attempted the store,
    False on a cache hit (including a waiter that read the leader's row).
    *compute* runs only for the leader of a concurrent miss; if the leader
    fails, waiters re-enter so one of them becomes the next leader rather than
    every waiter spawning the engine.  The computed text is returned even when
    :func:`set_disasm` refuses the write (a concurrent identity change).
    """
    hit = get_disasm(conn, function_id)
    if hit is not None:
        return hit, False
    with _DISASM_GATES_LOCK:
        gate = _DISASM_GATES.get(function_id)
        leader = gate is None
        if leader:
            gate = threading.Event()
            _DISASM_GATES[function_id] = gate
    assert gate is not None
    if not leader:
        gate.wait()
        hit = get_disasm(conn, function_id)
        if hit is not None:
            return hit, False
        return get_or_compute_disasm(
            conn,
            function_id,
            compute,
            extent_size=extent_size,
            project_dir=project_dir,
        )
    try:
        text = compute()
        set_disasm(
            conn,
            function_id,
            text,
            extent_size=extent_size,
            project_dir=project_dir,
        )
        return text, True
    finally:
        gate.set()
        with _DISASM_GATES_LOCK:
            _DISASM_GATES.pop(function_id, None)


def clear_disasm_for_binary(conn: sqlite3.Connection, binary_id: int) -> int:
    """Drop every cached listing belonging to *binary_id*; returns how many went."""
    cur = conn.execute(
        "DELETE FROM disasm_cache WHERE function_id IN ("
        " SELECT f.id FROM functions f"
        " JOIN analyses a ON a.id = f.analysis_id"
        " WHERE a.binary_id = ?)",
        (binary_id,),
    )
    conn.commit()
    return int(cur.rowcount)


# ── Decompilations ─────────────────────────────────────────────────


def set_decompilation(
    conn: sqlite3.Connection,
    function_id: int,
    code: str,
    backend: str,
    *,
    named: bool = False,
) -> None:
    """Store the decompiled source of *function_id*, replacing any earlier one."""
    conn.execute(
        "INSERT INTO decompilations (function_id, code, backend, named, created_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(function_id) DO UPDATE SET code = excluded.code,"
        " backend = excluded.backend, named = excluded.named,"
        " created_at = excluded.created_at",
        (function_id, code, backend, 1 if named else 0, now()),
    )
    conn.commit()


def get_decompilation(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """Return the stored decompilation of *function_id*, or None.

    The row is ``{"code", "backend", "named", "created_at"}``; the backend that
    produced the source is kept so a caller can report it.
    """
    return decompilations_for_functions(conn, [function_id]).get(int(function_id))


def decompilations_for_functions(
    conn: sqlite3.Connection, function_ids: Sequence[int]
) -> dict[int, dict[str, Any]]:
    """Stored decompilations for many functions in one query, keyed by id.

    An id with no stored decompilation is absent from the map.
    """
    if not function_ids:
        return {}
    ids = [int(function_id) for function_id in function_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        "SELECT function_id, code, backend, named, created_at FROM decompilations"
        f" WHERE function_id IN ({placeholders})",
        ids,
    )
    return {
        int(row["function_id"]): {
            "code": row["code"],
            "backend": row["backend"],
            "named": bool(row["named"]),
            "created_at": row["created_at"],
        }
        for row in cur.fetchall()
    }


def decompilations_for_binary(
    conn: sqlite3.Connection, binary_id: int
) -> dict[int, dict[str, Any]]:
    """Every stored decompilation belonging to *binary_id*, keyed by function id."""
    cur = conn.execute(
        """
        SELECT d.function_id AS function_id, d.code AS code, d.backend AS backend,
               d.named AS named, d.created_at AS created_at
        FROM decompilations d
        JOIN functions f ON d.function_id = f.id
        JOIN analyses a ON a.id = f.analysis_id
        WHERE a.binary_id = ?
        """,
        (binary_id,),
    )
    return {
        int(row["function_id"]): {
            "code": row["code"],
            "backend": row["backend"],
            "named": bool(row["named"]),
            "created_at": row["created_at"],
        }
        for row in cur.fetchall()
    }


def decompilation_ids_for_binary(conn: sqlite3.Connection, binary_id: int) -> set[int]:
    """The function ids of *binary_id* that carry a stored decompilation.

    Existence only: a rollup that only needs the boolean never pulls the
    source text.
    """
    cur = conn.execute(
        """
        SELECT d.function_id AS function_id
        FROM decompilations d
        JOIN functions f ON d.function_id = f.id
        JOIN analyses a ON a.id = f.analysis_id
        WHERE a.binary_id = ?
        """,
        (binary_id,),
    )
    return {int(row["function_id"]) for row in cur.fetchall()}


def clear_decompilation(conn: sqlite3.Connection, function_id: int) -> bool:
    """Drop the stored decompilation of *function_id*; False when there was none."""
    cur = conn.execute("DELETE FROM decompilations WHERE function_id = ?", (function_id,))
    conn.commit()
    return cur.rowcount > 0


# ── AI artifacts ───────────────────────────────────────────────────


def set_ai_artifact(
    conn: sqlite3.Connection, function_id: int, kind: str, payload: dict[str, Any], model: str
) -> None:
    """Store one AI artifact of *function_id*, replacing any earlier one.

    The ``(function_id, kind)`` primary key makes a re-run refresh the artifact
    instead of adding a row.
    """
    conn.execute(
        "INSERT INTO ai_artifacts (function_id, kind, payload_json, model, created_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(function_id, kind) DO UPDATE SET payload_json = excluded.payload_json,"
        " model = excluded.model, created_at = excluded.created_at",
        (function_id, kind, json.dumps(payload), model, now()),
    )
    conn.commit()


def get_ai_artifact(conn: sqlite3.Connection, function_id: int, kind: str) -> dict[str, Any] | None:
    """Return the stored artifact of *kind*, or None (also for an unparsable payload).

    The row is ``{"kind", "payload", "model", "created_at"}``.
    """
    row = conn.execute(
        "SELECT kind, payload_json, model, created_at FROM ai_artifacts"
        " WHERE function_id = ? AND kind = ?",
        (function_id, kind),
    ).fetchone()
    return _artifact_row(row) if row else None


def list_ai_artifacts(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """Stored artifacts of *function_id*, ordered by kind, each with its payload."""
    cur = conn.execute(
        "SELECT kind, payload_json, model, created_at FROM ai_artifacts"
        " WHERE function_id = ? ORDER BY kind",
        (function_id,),
    )
    return [row for row in (_artifact_row(entry) for entry in cur.fetchall()) if row is not None]


def clear_ai_artifact(
    conn: sqlite3.Connection, function_id: int, kind: str, *, commit: bool = True
) -> bool:
    """Drop one stored AI artifact; False when the function had none of *kind*.

    Pass ``commit=False`` when the caller journals the clear and will commit
    the delete with the journal entry in one transaction.
    """
    cur = conn.execute(
        "DELETE FROM ai_artifacts WHERE function_id = ? AND kind = ?", (function_id, kind)
    )
    if commit:
        conn.commit()
    return cur.rowcount > 0


def _artifact_row(row: sqlite3.Row) -> dict[str, Any] | None:
    """Return one ``ai_artifacts`` row as a parsed dict, or None when unusable."""
    try:
        payload = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return {
        "kind": str(row["kind"]),
        "payload": payload,
        "model": str(row["model"]),
        "created_at": str(row["created_at"]),
    }


# ── Scans ──────────────────────────────────────────────────────────


def _scan_params_json(params: Mapping[str, Any] | None) -> str:
    """The recorded inputs as a JSON object, so a reader can always index it."""
    return json.dumps(dict(params)) if params else "{}"


def set_scan(
    conn: sqlite3.Connection,
    analysis_id: int,
    kind: str,
    result: dict[str, Any],
    *,
    params: Mapping[str, Any] | None = None,
) -> None:
    """Store *result* as the scan of *kind* on *analysis_id*, replacing any earlier one.

    *params* are the caller-named inputs the run used (a decompiler, a severity
    floor, the other binary of a comparison).  They are stored beside the result
    rather than inside it: an engine payload is stored exactly as the engine
    returned it, so a reader that wants to replay a scan needs the inputs the
    caller chose, which the payload does not carry.

    A stored scan is a finished scan, so this records the finish in the
    analysis's log and leaves the analysis `done`: the scan ran to completion.
    A scan whose engine call raised never reaches here; the caller that wraps
    it with :func:`scan_span` records the failure instead.
    """
    conn.execute(
        "INSERT INTO scans (analysis_id, kind, status, result_json, params_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(analysis_id, kind) DO UPDATE SET status = excluded.status,"
        " result_json = excluded.result_json, params_json = excluded.params_json,"
        " created_at = excluded.created_at",
        (analysis_id, kind, SCAN_STATUS_DONE, json.dumps(result), _scan_params_json(params), now()),
    )
    conn.commit()
    analysis_log.append_entry(conn, analysis_id, message=f"{kind} scan finished")
    update_analysis_status(conn, analysis_id, status=ANALYSIS_STATUS_DONE)


def get_scan(conn: sqlite3.Connection, analysis_id: int, kind: str) -> dict[str, Any] | None:
    """Return the stored scan of *kind*, or None (also for an unparsable payload)."""
    row = conn.execute(
        "SELECT result_json FROM scans WHERE analysis_id = ? AND kind = ?",
        (analysis_id, kind),
    ).fetchone()
    if row is None:
        return None
    try:
        stored = json.loads(str(row["result_json"]))
    except json.JSONDecodeError:
        return None
    return stored if isinstance(stored, dict) else None


def get_scan_params(conn: sqlite3.Connection, analysis_id: int, kind: str) -> dict[str, Any]:
    """The inputs a stored scan recorded, or {} when it recorded none."""
    row = conn.execute(
        "SELECT params_json FROM scans WHERE analysis_id = ? AND kind = ?",
        (analysis_id, kind),
    ).fetchone()
    if row is None:
        return {}
    try:
        stored = json.loads(str(row["params_json"]) or "{}")
    except json.JSONDecodeError:
        return {}
    return dict(stored) if isinstance(stored, dict) else {}


def list_scans(conn: sqlite3.Connection, analysis_id: int) -> list[dict[str, Any]]:
    """Scans of *analysis_id*, newest first, with their recorded inputs.

    The result payload is left out (it can be large and the caller that wants it
    asks for the scan); the recorded inputs are included, which is what makes a
    listing answer "what ran here, and with what".
    """
    cur = conn.execute(
        "SELECT id, analysis_id, kind, status, params_json, created_at FROM scans"
        " WHERE analysis_id = ? ORDER BY id DESC",
        (analysis_id,),
    )
    rows = _rows(cur)
    for row in rows:
        try:
            stored = json.loads(str(row.pop("params_json") or "{}"))
        except json.JSONDecodeError:
            stored = {}
        row["params"] = dict(stored) if isinstance(stored, dict) else {}
    return rows


# ── Pipeline runs ──────────────────────────────────────────────────


def _json_list(raw: Any) -> list[Any]:
    """Parse a JSON array column, returning [] when it is unusable."""
    text = str(raw)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        if text.strip() and text.strip() != "[]":
            _log.warning("corrupt JSON array column: %s", exc)
        return []
    if isinstance(parsed, list):
        return parsed
    if text.strip() and text.strip() != "[]":
        _log.warning("JSON array column is not a list: %s", type(parsed).__name__)
    return []


# A row mapper is a field spec: ``(output key, column, converter)``.  Plain
# columns convert with int/str/float; a ``*_json`` column converts with the
# JSON helper beside it.  One spec table per row shape replaces a dozen
# near-identical ``_*_row`` functions that differed only in these triples.
_RowField = tuple[str, str, Any]


def _map_row(row: sqlite3.Row, fields: tuple[_RowField, ...]) -> dict[str, Any]:
    """Build one row dict from *fields*."""
    return {key: convert(row[column]) for key, column, convert in fields}


_PIPELINE_STEP_FIELDS: tuple[_RowField, ...] = (
    ("id", "id", int),
    ("run_id", "run_id", int),
    ("name", "name", str),
    ("status", "status", str),
    ("reason", "reason", str),
    ("started_at", "started_at", str),
    ("finished_at", "finished_at", str),
    ("duration_ms", "duration_ms", int),
    ("provides", "provides_json", _json_list),
)


def _pipeline_step_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``pipeline_steps`` row with its provided names parsed from JSON."""
    return _map_row(row, _PIPELINE_STEP_FIELDS)


def _pipeline_run_row(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """One ``pipeline_runs`` row with its steps and its undo plan."""
    return {
        "id": int(row["id"]),
        "function_id": int(row["function_id"]),
        "status": str(row["status"]),
        "started_at": str(row["started_at"]),
        "finished_at": str(row["finished_at"]) if row["finished_at"] is not None else None,
        "model": str(row["model"]),
        "created_at": str(row["created_at"]),
        "effects": _json_list(row["effects_json"]),
        "steps": list_pipeline_steps(conn, int(row["id"])),
    }


def create_pipeline_run(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    model: str = "",
    started_at: str | None = None,
) -> int:
    """Create a ``running`` pipeline run for *function_id*; returns its id."""
    cur = conn.execute(
        "INSERT INTO pipeline_runs (function_id, status, started_at, model, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (function_id, PIPELINE_RUN_RUNNING, started_at or now(), model, now()),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def finish_pipeline_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str,
    effects: Sequence[dict[str, Any]] = (),
    finished_at: str | None = None,
) -> bool:
    """Close a running run with a terminal *status* and the undo plan of its writes.

    *status* must be one of :data:`PIPELINE_RUN_FINISH_STATUSES`.  Only a
    ``running`` row is updated.
    """
    if status not in PIPELINE_RUN_FINISH_STATUSES:
        raise ValueError(
            f"invalid pipeline-run finish status {status!r};"
            f" expected one of {', '.join(sorted(PIPELINE_RUN_FINISH_STATUSES))}"
        )
    cur = conn.execute(
        "UPDATE pipeline_runs SET status = ?, finished_at = ?, effects_json = ?"
        " WHERE id = ? AND status = ?",
        (status, finished_at or now(), json.dumps(list(effects)), run_id, PIPELINE_RUN_RUNNING),
    )
    conn.commit()
    return cur.rowcount > 0


def set_pipeline_effects(
    conn: sqlite3.Connection, run_id: int, effects: Sequence[dict[str, Any]]
) -> bool:
    """Replace a run's undo plan, which a revert consumes; False for an unknown id."""
    cur = conn.execute(
        "UPDATE pipeline_runs SET effects_json = ? WHERE id = ?",
        (json.dumps(list(effects)), run_id),
    )
    conn.commit()
    return cur.rowcount > 0


def add_pipeline_step(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    name: str,
    status: str,
    reason: str = "",
    started_at: str = "",
    finished_at: str = "",
    duration_ms: int = 0,
    provides: Sequence[str] = (),
) -> int:
    """Append one step of a run; returns its id."""
    cur = conn.execute(
        "INSERT INTO pipeline_steps (run_id, name, status, reason, started_at, finished_at,"
        " duration_ms, provides_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            name,
            status,
            reason,
            started_at,
            finished_at,
            duration_ms,
            json.dumps(list(provides)),
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_pipeline_steps(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Steps of a run in the order the components ran."""
    cur = conn.execute("SELECT * FROM pipeline_steps WHERE run_id = ? ORDER BY id", (run_id,))
    return [_pipeline_step_row(row) for row in cur.fetchall()]


def get_pipeline_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """One run with its steps and undo plan, or None."""
    row = conn.execute("SELECT * FROM pipeline_runs WHERE id = ?", (run_id,)).fetchone()
    return _pipeline_run_row(conn, row) if row else None


def latest_pipeline_run(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """Newest run of *function_id* with its steps and undo plan, or None."""
    row = conn.execute(
        "SELECT * FROM pipeline_runs WHERE function_id = ? ORDER BY id DESC LIMIT 1",
        (function_id,),
    ).fetchone()
    return _pipeline_run_row(conn, row) if row else None


def delete_pipeline_run(conn: sqlite3.Connection, run_id: int) -> bool:
    """Delete a run and, by cascade, its steps; False for an unknown id."""
    cur = conn.execute("DELETE FROM pipeline_runs WHERE id = ?", (run_id,))
    conn.commit()
    return cur.rowcount > 0


# ── Rename history ─────────────────────────────────────────────────


def rename_function(
    conn: sqlite3.Connection,
    function_id: int,
    *,
    new_name: str,
    actor: str,
    source: str = "manual",
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    """Rename a function and append the change to ``name_history``.

    The name is stripped and NFC-normalized so a padded or NFD spelling
    (typical of text pasted from macOS) matches the stored form and does not
    open a spurious history row.  Raises ValueError for a blank name and
    KeyError for an unknown function.  Returns
    ``{function_id, old_name, new_name}``.
    """
    cleaned = unicodedata.normalize("NFC", new_name.strip())
    if not cleaned:
        raise ValueError("new_name must not be empty")
    row = conn.execute("SELECT name FROM functions WHERE id = ?", (function_id,)).fetchone()
    if row is None:
        raise KeyError(f"no function with id {function_id}")
    old_name = str(row["name"])
    if unicodedata.normalize("NFC", old_name) == cleaned:
        return {"function_id": function_id, "old_name": old_name, "new_name": cleaned}
    conn.execute(
        "INSERT INTO name_history"
        " (function_id, old_name, new_name, source, actor, actor_user_id, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (function_id, old_name, cleaned, source, actor, actor_user_id, now()),
    )
    conn.execute(
        "UPDATE functions SET name = ?, name_source = ? WHERE id = ?",
        (cleaned, source, function_id),
    )
    conn.commit()
    return {"function_id": function_id, "old_name": old_name, "new_name": cleaned}


def list_name_history(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """Rename history for a function, newest first."""
    cur = conn.execute(
        "SELECT * FROM name_history WHERE function_id = ? ORDER BY id DESC",
        (function_id,),
    )
    return _rows(cur)


def get_name_history(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One rename-history row by id, or None."""
    row = conn.execute("SELECT * FROM name_history WHERE id = ?", (history_id,)).fetchone()
    return dict(row) if row else None


def revert_name(
    conn: sqlite3.Connection,
    history_id: int,
    *,
    actor: str = "revert",
    actor_user_id: int | None = None,
) -> int:
    """Restore the pre-rename name recorded by *history_id*; returns function id.

    The revert itself is recorded in ``name_history`` (source ``revert``), so
    every name a function ever had stays traceable.
    """
    row = conn.execute(
        "SELECT function_id, old_name FROM name_history WHERE id = ?", (history_id,)
    ).fetchone()
    if row is None:
        raise KeyError(f"no name_history row with id {history_id}")
    function_id = int(row["function_id"])
    rename_function(
        conn,
        function_id,
        new_name=str(row["old_name"]),
        actor=actor,
        source="revert",
        actor_user_id=actor_user_id,
    )
    return function_id


# ── Collections ────────────────────────────────────────────────────


def _has_label_controls(cleaned: str) -> bool:
    """True when *cleaned* carries a control, format, or separator character.

    ASCII C0 controls and DEL are refused, and so are Unicode format characters
    (zero-width spaces, bidi controls) and line/paragraph separators that would
    otherwise look blank in a name while still distinguishing two identities.
    Matches the policy :mod:`reportal.auth` applies to user and team names.
    """
    return any(
        ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"}
        for ch in cleaned
    )


def _canonical_label(name: str) -> str:
    """Strip padding and NFC-normalize a tag or collection name.

    Identity lookups and writes share this form so an NFD spelling (typical of
    macOS filenames pasted into a name) matches the NFC row already stored,
    and so create/find/rename cannot disagree about padding alone.
    """
    return unicodedata.normalize("NFC", name.strip())


def _validated_label(name: str, *, kind: str) -> str:
    """Canonical form of *name*, or raise ``ValueError`` when blank or hostile."""
    cleaned = _canonical_label(name)
    if not cleaned:
        raise ValueError(f"{kind} name must not be empty")
    if _has_label_controls(cleaned):
        raise ValueError(f"{kind} name must not contain control characters")
    return cleaned


def create_collection(
    conn: sqlite3.Connection, *, name: str, description: str = "", scope: str = ""
) -> int:
    """Create a collection; raises ValueError when the name is taken.

    The stored name is stripped and NFC-normalized so a padded or NFD create
    cannot collide with a later rename that canonicalizes the same way, and so
    uniqueness matches what callers see.  Control and format characters are
    refused the same way auth refuses them on identity names.
    """
    cleaned = _validated_label(name, kind="collection")
    try:
        cur = conn.execute(
            "INSERT INTO collections (name, description, scope, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (cleaned, description, scope, now(), now()),
        )
    except sqlite3.IntegrityError:
        raise ValueError(f"collection {cleaned!r} already exists") from None
    conn.commit()
    return int(cur.lastrowid or 0)


# The orders :func:`list_collections` accepts, with the SQL each one sorts by.
# ``size`` counts member binaries, largest first, so the collections holding the
# most work read first; ``updated`` is newest change first.
COLLECTION_ORDERS: dict[str, str] = {
    "id": "c.id ASC",
    "name": "c.name COLLATE NOCASE ASC, c.id ASC",
    "size": "binary_count DESC, c.name COLLATE NOCASE ASC, c.id ASC",
    "updated": "c.updated_at DESC, c.id DESC",
    # ``owner`` sorts by the owning team's name; a collection no team owns (the
    # personal ones) has no name to sort by and reads first, which is what
    # ``t.name IS NOT NULL`` puts there.
    "owner": "t.name IS NOT NULL, t.name COLLATE NOCASE ASC, c.id ASC",
}

DEFAULT_COLLECTION_ORDER = "id"


def list_collections(
    conn: sqlite3.Connection,
    *,
    order: str = DEFAULT_COLLECTION_ORDER,
    workspace: str | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """All collections with their member-binary count, in *order*.

    *order* is one of :data:`COLLECTION_ORDERS`; an unknown one raises
    ``ValueError``, which the API, the CLI and the MCP tools map to their own
    error vocabulary.  *workspace* is one of :data:`WORKSPACE_FILTERS` and reads
    a collection's own scope the way :func:`list_analyses` reads an analysis's:
    ``personal`` is one no team owns, ``team`` one a team does, and ``public``
    one the whole workspace may see.  Each row carries that scope
    (``visibility``, ``owner_team_id``) and the owning team's name as
    ``owner_team_name``, which is null for a personal collection.  *visible_to*
    narrows the listing the way :func:`list_binaries` does.
    """
    if order not in COLLECTION_ORDERS:
        raise ValueError(f"unknown collection order: {order}")
    if workspace is not None and workspace not in WORKSPACE_FILTERS:
        raise ValueError(f"unknown workspace filter: {workspace}")
    sql = (
        "SELECT c.*, (SELECT COUNT(*) FROM collection_binaries cb"
        " WHERE cb.collection_id = c.id) AS binary_count,"
        " t.name AS owner_team_name FROM collections c"
        " LEFT JOIN teams t ON t.id = c.owner_team_id"
    )
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="c.")
    if scope is not None:
        clauses.append(scope[0])
        params.extend(scope[1])
    if workspace == WORKSPACE_PERSONAL:
        clauses.append("c.owner_team_id IS NULL")
    elif workspace == WORKSPACE_TEAM:
        clauses.append("c.owner_team_id IS NOT NULL")
    elif workspace == WORKSPACE_PUBLIC:
        clauses.append("c.visibility = ?")
        params.append("public")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += f" ORDER BY {COLLECTION_ORDERS[order]}"
    return _rows(conn.execute(sql, params))


def collections_of_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """The collections *binary_id* is a member of, each row as the listing's.

    A row carries the collection's own fields, its member count and its owning
    team's name, the shape :func:`list_collections` returns, and *visible_to*
    narrows it the same way: a collection the caller may not see is not
    disclosed by a binary it can.
    """
    sql = (
        "SELECT c.*, (SELECT COUNT(*) FROM collection_binaries cb2"
        " WHERE cb2.collection_id = c.id) AS binary_count,"
        " t.name AS owner_team_name FROM collections c"
        " JOIN collection_binaries cb ON cb.collection_id = c.id"
        " LEFT JOIN teams t ON t.id = c.owner_team_id"
        " WHERE cb.binary_id = ?"
    )
    params: list[Any] = [binary_id]
    scope = auth.visible_clause(conn, visible_to, prefix="c.")
    if scope is not None:
        sql += " AND " + scope[0]
        params.extend(scope[1])
    sql += " ORDER BY c.name, c.id"
    return _rows(conn.execute(sql, params))


# ── Feedback ───────────────────────────────────────────────────────

# A feedback note is free text; this is the bound the hosted form implies and
# the one the API, the CLI and the MCP tool all enforce.
MAX_FEEDBACK_CHARS = 2000


class InvalidFeedbackError(ValueError):
    """The note is blank or past :data:`MAX_FEEDBACK_CHARS`."""


def add_feedback(
    conn: sqlite3.Connection, *, body: str, actor: str = "", user_id: int | None = None
) -> int:
    """Store one feedback note; returns its id.

    *actor* is the name the request recorded (empty for a CLI invocation) and
    *user_id* the authenticated user when there is one, so a note written by a
    signed-in caller is attributable and one written with auth off is not
    invented into an owner.
    """
    cleaned = (body or "").strip()
    if not cleaned:
        raise InvalidFeedbackError("the message must not be blank")
    if len(cleaned) > MAX_FEEDBACK_CHARS:
        raise InvalidFeedbackError(f"the message must be at most {MAX_FEEDBACK_CHARS} characters")
    cursor = conn.execute(
        "INSERT INTO feedback (user_id, actor, body, created_at) VALUES (?, ?, ?, ?)",
        (user_id, actor, cleaned, now()),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def get_feedback(conn: sqlite3.Connection, feedback_id: int) -> dict[str, Any] | None:
    """One feedback note, or None when the id is unknown."""
    row = conn.execute("SELECT * FROM feedback WHERE id = ?", (feedback_id,)).fetchone()
    return dict(row) if row else None


def list_feedback(
    conn: sqlite3.Connection, *, limit: int = 50, user_id: int | None = None
) -> list[dict[str, Any]]:
    """Feedback notes, newest first, bounded.

    *user_id* narrows the page to one owner's notes; ``None`` is every note.
    """
    bounded = max(1, min(int(limit), 500))
    if user_id is None:
        return _rows(conn.execute("SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (bounded,)))
    return _rows(
        conn.execute(
            "SELECT * FROM feedback WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, bounded),
        )
    )


def count_feedback(conn: sqlite3.Connection, *, user_id: int | None = None) -> int:
    """How many feedback notes are stored, whatever a reader's page is.

    *user_id* counts one owner's notes; ``None`` counts every note.
    """
    if user_id is None:
        return int(conn.execute("SELECT COUNT(*) AS n FROM feedback").fetchone()["n"])
    return int(
        conn.execute("SELECT COUNT(*) AS n FROM feedback WHERE user_id = ?", (user_id,)).fetchone()[
            "n"
        ]
    )


def set_binary_scope(
    conn: sqlite3.Connection, binary_id: int, *, owner_team_id: int | None, visibility: str
) -> dict[str, Any] | None:
    """Set which team owns a binary and whether the workspace may see it."""
    if get_binary(conn, binary_id) is None:
        return None
    conn.execute(
        "UPDATE binaries SET owner_team_id = ?, visibility = ? WHERE id = ?",
        (owner_team_id, visibility, binary_id),
    )
    conn.commit()
    return get_binary(conn, binary_id)


def set_collection_scope(
    conn: sqlite3.Connection, collection_id: int, *, owner_team_id: int | None, visibility: str
) -> dict[str, Any] | None:
    """Set which team owns a collection and whether the workspace may see it."""
    if get_collection(conn, collection_id) is None:
        return None
    conn.execute(
        "UPDATE collections SET owner_team_id = ?, visibility = ?, updated_at = ? WHERE id = ?",
        (owner_team_id, visibility, now(), collection_id),
    )
    conn.commit()
    return get_collection(conn, collection_id)


def touch_collection(conn: sqlite3.Connection, collection_id: int) -> None:
    """Record that a collection changed now; the caller commits."""
    conn.execute("UPDATE collections SET updated_at = ? WHERE id = ?", (now(), collection_id))


def find_collection_by_name(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One collection row by exact name, or None; unlike :func:`create_collection`.

    Archive extraction reuses a collection named after the archive instead of
    failing on the name it would create a second time.  The lookup uses the same
    strip-and-NFC form as :func:`create_collection`, so a padded or NFD query
    finds the stored row rather than minting a duplicate.
    """
    row = conn.execute(
        """
        SELECT c.*, (
            SELECT COUNT(*) FROM collection_binaries cb WHERE cb.collection_id = c.id
        ) AS binary_count
        FROM collections c WHERE c.name = ?
        """,
        (_canonical_label(name),),
    ).fetchone()
    return dict(row) if row else None


def add_collection_binary(conn: sqlite3.Connection, collection_id: int, binary_id: int) -> bool:
    """Add a binary to a collection; False when it was already a member."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO collection_binaries (collection_id, binary_id) VALUES (?, ?)",
        (collection_id, binary_id),
    )
    conn.commit()
    return cur.rowcount > 0


def remove_collection_binary(conn: sqlite3.Connection, collection_id: int, binary_id: int) -> bool:
    """Remove a binary from a collection; False when it was not a member."""
    cur = conn.execute(
        "DELETE FROM collection_binaries WHERE collection_id = ? AND binary_id = ?",
        (collection_id, binary_id),
    )
    conn.commit()
    return cur.rowcount > 0


def collection_binaries(conn: sqlite3.Connection, collection_id: int) -> list[dict[str, Any]]:
    """The members of one collection, each ``{id, name, sha256, size}``, by name."""
    cur = conn.execute(
        "SELECT b.id, b.name, b.sha256, b.size FROM binaries b"
        " JOIN collection_binaries cb ON cb.binary_id = b.id"
        " WHERE cb.collection_id = ? ORDER BY b.name, b.id",
        (collection_id,),
    )
    return _rows(cur)


def collection_tags(conn: sqlite3.Connection, collection_id: int) -> list[dict[str, Any]]:
    """Tags applied to one collection, each ``{id, name}``, ordered by name."""
    cur = conn.execute(
        "SELECT t.id, t.name FROM tags t"
        " JOIN collection_tags ct ON ct.tag_id = t.id"
        " WHERE ct.collection_id = ? ORDER BY t.name",
        (collection_id,),
    )
    return _rows(cur)


def collection_tag_names(
    conn: sqlite3.Connection, collection_ids: Sequence[int]
) -> dict[int, list[str]]:
    """Tag names for many collections in one query, keyed by collection id.

    Missing ids are absent from the map; callers that need a name list for every
    listed collection can fall back to ``.get(id, [])``.
    """
    ids = [int(collection_id) for collection_id in collection_ids]
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        "SELECT ct.collection_id AS collection_id, t.name AS name FROM tags t"
        " JOIN collection_tags ct ON ct.tag_id = t.id"
        f" WHERE ct.collection_id IN ({placeholders}) ORDER BY t.name",
        ids,
    )
    names: dict[int, list[str]] = {}
    for row in cur:
        names.setdefault(int(row["collection_id"]), []).append(str(row["name"]))
    return names


def get_collection(conn: sqlite3.Connection, collection_id: int) -> dict[str, Any] | None:
    """One collection with its member binaries and tags, or None."""
    row = conn.execute(
        """
        SELECT c.*, (
            SELECT COUNT(*) FROM collection_binaries cb WHERE cb.collection_id = c.id
        ) AS binary_count
        FROM collections c WHERE c.id = ?
        """,
        (collection_id,),
    ).fetchone()
    if row is None:
        return None
    collection = dict(row)
    collection["binaries"] = collection_binaries(conn, collection_id)
    collection["tags"] = collection_tags(conn, collection_id)
    return collection


def update_collection(
    conn: sqlite3.Connection,
    collection_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
    scope: str | None = None,
) -> dict[str, Any] | None:
    """Set the fields given on one collection; None when the id is unknown.

    A name that is empty or already taken raises ``ValueError``, the same rule
    :func:`create_collection` applies, so a rename cannot break the unique name.
    A field left out is not touched.
    """
    if get_collection(conn, collection_id) is None:
        return None
    updates: list[str] = []
    params: list[Any] = []
    if name is not None:
        cleaned = _validated_label(name, kind="collection")
        clash = conn.execute(
            "SELECT 1 FROM collections WHERE name = ? AND id != ?", (cleaned, collection_id)
        ).fetchone()
        if clash:
            raise ValueError(f"collection {cleaned!r} already exists")
        updates.append("name = ?")
        params.append(cleaned)
    if description is not None:
        updates.append("description = ?")
        params.append(description)
    if scope is not None:
        updates.append("scope = ?")
        params.append(scope)
    if updates:
        updates.append("updated_at = ?")
        params.append(now())
        params.append(collection_id)
        conn.execute(f"UPDATE collections SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
    return get_collection(conn, collection_id)


def delete_collection(conn: sqlite3.Connection, collection_id: int) -> bool:
    """Delete one collection with its membership and tag links; False when unknown."""
    if get_collection(conn, collection_id) is None:
        return False
    conn.execute("DELETE FROM collection_binaries WHERE collection_id = ?", (collection_id,))
    conn.execute("DELETE FROM collection_tags WHERE collection_id = ?", (collection_id,))
    conn.execute("DELETE FROM collections WHERE id = ?", (collection_id,))
    conn.commit()
    return True


def replace_collection_binaries(
    conn: sqlite3.Connection, collection_id: int, binary_ids: Sequence[int]
) -> dict[str, Any]:
    """Make *binary_ids* the exact members of one collection.

    Every id is checked before anything is written: an id that names no binary
    raises ``ValueError`` naming it, so a typo cannot silently empty or half
    rewrite a collection.  Returns the ids added, removed and kept.
    """
    if get_collection(conn, collection_id) is None:
        raise KeyError(f"no collection with id {collection_id}")
    wanted = list(dict.fromkeys(binary_ids))
    if wanted:
        placeholders = ", ".join("?" for _ in wanted)
        known = {
            int(row["id"])
            for row in conn.execute(f"SELECT id FROM binaries WHERE id IN ({placeholders})", wanted)
        }
        missing = [binary_id for binary_id in wanted if binary_id not in known]
        if missing:
            raise ValueError(f"no binary with id {missing[0]}")
    current = {int(row["id"]) for row in collection_binaries(conn, collection_id)}
    target = set(wanted)
    added = sorted(target - current)
    removed = sorted(current - target)
    for binary_id in added:
        conn.execute(
            "INSERT OR IGNORE INTO collection_binaries (collection_id, binary_id) VALUES (?, ?)",
            (collection_id, binary_id),
        )
    for binary_id in removed:
        conn.execute(
            "DELETE FROM collection_binaries WHERE collection_id = ? AND binary_id = ?",
            (collection_id, binary_id),
        )
    if added or removed:
        touch_collection(conn, collection_id)
    conn.commit()
    return {"added": added, "removed": removed, "kept": sorted(current & target)}


def set_collection_tags(
    conn: sqlite3.Connection, collection_id: int, names: Sequence[str]
) -> dict[str, Any]:
    """Replace the tags on one collection, creating the names that are new.

    Returns the tag names added and removed, so a caller can report and journal
    the change.  An unknown collection raises ``KeyError``.
    """
    if get_collection(conn, collection_id) is None:
        raise KeyError(f"no collection with id {collection_id}")
    wanted: set[str] = set()
    for name in names:
        cleaned = _canonical_label(name)
        if not cleaned:
            continue
        if _has_label_controls(cleaned):
            raise ValueError("tag name must not contain control characters")
        wanted.add(cleaned)
    current = {str(tag["name"]) for tag in collection_tags(conn, collection_id)}
    added = sorted(wanted - current)
    removed = sorted(current - wanted)
    for name in added:
        tag_id = create_tag(conn, name)
        conn.execute(
            "INSERT OR IGNORE INTO collection_tags (collection_id, tag_id) VALUES (?, ?)",
            (collection_id, tag_id),
        )
    for name in removed:
        conn.execute(
            "DELETE FROM collection_tags WHERE collection_id = ? AND tag_id ="
            " (SELECT id FROM tags WHERE name = ?)",
            (collection_id, name),
        )
    if added or removed:
        touch_collection(conn, collection_id)
    conn.commit()
    return {"added": added, "removed": removed}


# ── Tags ───────────────────────────────────────────────────────────


def create_tag(conn: sqlite3.Connection, name: str) -> int:
    """Return the id of tag *name*, creating it when new.

    Leading and trailing whitespace are stripped and the name is NFC-normalized
    so a padded or NFD create matches :func:`rename_tag` and :func:`find_tag`,
    and cannot mint a second tag that only differs by surrounding spaces or
    combining-mark spelling.  Control and format characters are refused the
    same way auth refuses them on identity names.
    """
    cleaned = _validated_label(name, kind="tag")
    conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (cleaned,))
    conn.commit()
    row = conn.execute("SELECT id FROM tags WHERE name = ?", (cleaned,)).fetchone()
    return int(row["id"]) if row else 0


def list_tags(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """All tags with their tagged-binary and tagged-collection counts."""
    cur = conn.execute(
        """
        SELECT t.*, (
            SELECT COUNT(*) FROM binary_tags bt WHERE bt.tag_id = t.id
        ) AS binary_count, (
            SELECT COUNT(*) FROM collection_tags ct WHERE ct.tag_id = t.id
        ) AS collection_count
        FROM tags t ORDER BY t.name
        """
    )
    return _rows(cur)


def rename_tag(conn: sqlite3.Connection, tag_id: int, name: str) -> dict[str, Any] | None:
    """Rename one tag; None for an unknown id.

    A blank name or one another tag already holds raises ``ValueError``, which
    the API, the CLI and the MCP tools map to their own error vocabulary.  The
    name is matched exactly, the rule the ``tags.name`` unique index and
    :func:`create_tag` already use, so a case variant stays a tag of its own.
    """
    if get_tag(conn, tag_id) is None:
        return None
    cleaned = _validated_label(name, kind="tag")
    existing = find_tag(conn, cleaned)
    if existing is not None and int(existing["id"]) != tag_id:
        raise ValueError(f"a tag named {cleaned!r} already exists")
    conn.execute("UPDATE tags SET name = ? WHERE id = ?", (cleaned, tag_id))
    conn.commit()
    return get_tag(conn, tag_id)


def delete_tag(conn: sqlite3.Connection, tag_id: int) -> bool:
    """Delete one tag and every link to it; False for an unknown id.

    The links go with the row through the schema's ``ON DELETE CASCADE``, so a
    caller that journals them can put both back.
    """
    if get_tag(conn, tag_id) is None:
        return False
    conn.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    conn.commit()
    return True


def get_tag(conn: sqlite3.Connection, tag_id: int) -> dict[str, Any] | None:
    """One tag row by id, or None."""
    row = conn.execute("SELECT id, name FROM tags WHERE id = ?", (tag_id,)).fetchone()
    return dict(row) if row else None


def find_tag(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One tag row by exact name, or None; unlike :func:`create_tag` it never inserts.

    The lookup strips and NFC-normalizes the same way :func:`create_tag` and
    :func:`rename_tag` do, so a padded or NFD name resolves to the stored tag
    rather than missing it.
    """
    row = conn.execute(
        "SELECT id, name FROM tags WHERE name = ?", (_canonical_label(name),)
    ).fetchone()
    return dict(row) if row else None


def add_binary_tag(conn: sqlite3.Connection, binary_id: int, tag_id: int) -> bool:
    """Tag a binary; False when the tag was already applied."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO binary_tags (binary_id, tag_id) VALUES (?, ?)",
        (binary_id, tag_id),
    )
    conn.commit()
    return cur.rowcount > 0


def remove_binary_tag(conn: sqlite3.Connection, binary_id: int, tag_id: int) -> bool:
    """Untag a binary; False when the tag was not applied."""
    cur = conn.execute(
        "DELETE FROM binary_tags WHERE binary_id = ? AND tag_id = ?",
        (binary_id, tag_id),
    )
    conn.commit()
    return cur.rowcount > 0


def get_binary_tags(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Tags applied to *binary_id*, each ``{id, name}``, ordered by name."""
    return tags_for_binaries(conn, [binary_id]).get(int(binary_id), [])


def tags_for_binaries(
    conn: sqlite3.Connection, binary_ids: Sequence[int]
) -> dict[int, list[dict[str, Any]]]:
    """Tags applied to each of *binary_ids*, each ``{id, name}``, name order.

    One round trip for a batch read; an id with no tags is absent from the map.
    """
    grouped: dict[int, list[dict[str, Any]]] = {}
    if not binary_ids:
        return grouped
    ids = [int(binary_id) for binary_id in binary_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        "SELECT bt.binary_id AS binary_id, t.id AS id, t.name AS name FROM tags t"
        " JOIN binary_tags bt ON bt.tag_id = t.id"
        f" WHERE bt.binary_id IN ({placeholders}) ORDER BY t.name",
        ids,
    )
    for row in cur.fetchall():
        grouped.setdefault(int(row["binary_id"]), []).append(
            {"id": int(row["id"]), "name": str(row["name"])}
        )
    return grouped


def sha256_for_binaries(
    conn: sqlite3.Connection, binary_ids: Sequence[int]
) -> dict[int, str | None]:
    """The stored sha256 of each named binary, or None when the row has none.

    One round trip; avoids the function-count subquery :func:`get_binary` pays.
    An unknown id is absent from the map.
    """
    if not binary_ids:
        return {}
    ids = [int(binary_id) for binary_id in binary_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        f"SELECT id, sha256 FROM binaries WHERE id IN ({placeholders})",
        ids,
    )
    result: dict[int, str | None] = {}
    for row in cur.fetchall():
        value = row["sha256"]
        result[int(row["id"])] = str(value) if value else None
    return result


# ── Conversations ──────────────────────────────────────────────────


def create_conversation(
    conn: sqlite3.Connection, *, scope_kind: str, scope_id: int, title: str
) -> int:
    """Create a conversation scoped to ``(scope_kind, scope_id)``; returns its id.

    Only the title is validated here.  The scope is a loose reference by
    design: no table holds both functions and binaries, so the API is what
    rejects an unknown scope id before calling this.
    """
    if not title.strip():
        raise ValueError("conversation title must not be empty")
    cur = conn.execute(
        "INSERT INTO conversations (scope_kind, scope_id, title, created_at) VALUES (?, ?, ?, ?)",
        (scope_kind, scope_id, title, now()),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_conversations(
    conn: sqlite3.Connection,
    *,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Conversations, newest id last, each with its stored message count.

    ``visible_to`` drops binary/function-scoped conversations on binaries
    the caller may not see, like the other scoped reads; conversations of
    other scopes (docs, project) have no owning binary and stay.
    """
    sql = (
        "SELECT c.*, ("
        "  SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id"
        ") AS message_count FROM conversations c"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if scope_kind is not None:
        clauses.append("c.scope_kind = ?")
        params.append(scope_kind)
    if scope_id is not None:
        clauses.append("c.scope_id = ?")
        params.append(scope_id)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, scope_params = scope
        clauses.append(
            "((c.scope_kind != ? AND c.scope_kind != ?)"
            f" OR (c.scope_kind = ? AND EXISTS (SELECT 1 FROM binaries b"
            f" WHERE b.id = c.scope_id AND {clause}))"
            f" OR (c.scope_kind = ? AND EXISTS (SELECT 1 FROM functions f"
            " JOIN analyses a ON f.analysis_id = a.id"
            " JOIN binaries b ON a.binary_id = b.id"
            f" WHERE f.id = c.scope_id AND {clause})))"
        )
        params.extend(
            [
                "binary",
                "function",
                "binary",
                *scope_params,
                "function",
                *scope_params,
            ]
        )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY c.id"
    return _rows(conn.execute(sql, params))


def get_conversation(conn: sqlite3.Connection, conversation_id: int) -> dict[str, Any] | None:
    """One conversation with its message count, or None."""
    cur = conn.execute(
        "SELECT c.*, ("
        "  SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id"
        ") AS message_count FROM conversations c WHERE c.id = ?",
        (conversation_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def delete_conversation(conn: sqlite3.Connection, conversation_id: int) -> bool:
    """Delete a conversation and its messages; False when the id is unknown.

    The ``ON DELETE CASCADE`` on ``messages.conversation_id`` removes the
    messages, so a deleted conversation leaves no orphan rows.
    """
    cur = conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
    conn.commit()
    return cur.rowcount > 0


def add_message(
    conn: sqlite3.Connection, *, conversation_id: int, role: str, content: str
) -> dict[str, Any]:
    """Append one message to a conversation and return the stored row.

    The conversation must exist: the foreign key rejects an unknown id.
    """
    created_at = now()
    cur = conn.execute(
        "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, ?, ?, ?)",
        (conversation_id, role, content, created_at),
    )
    conn.commit()
    return {
        "id": int(cur.lastrowid or 0),
        "conversation_id": conversation_id,
        "role": role,
        "content": content,
        "created_at": created_at,
    }


def list_messages(conn: sqlite3.Connection, conversation_id: int) -> list[dict[str, Any]]:
    """Messages of a conversation in the order they were appended."""
    cur = conn.execute(
        "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,)
    )
    return _rows(cur)


def message_ids(conn: sqlite3.Connection, conversation_id: int) -> set[int]:
    """The message ids of a conversation, without loading message bodies."""
    return {
        int(row["id"])
        for row in conn.execute(
            "SELECT id FROM messages WHERE conversation_id = ?", (conversation_id,)
        )
    }


# ── Comments ───────────────────────────────────────────────────────


def add_comment(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    author: str,
    body: str,
    author_user_id: int | None = None,
) -> dict[str, Any]:
    """Store one comment on ``(scope_kind, scope_id)`` and return its row.

    Raises ValueError for a blank body.  The scope is a loose reference by
    design, like a conversation's: no table holds both functions and binaries,
    so ``reportal.comments`` is what rejects an unknown scope id.
    """
    if not body.strip():
        raise ValueError("comment body must not be empty")
    stamp = now()
    cur = conn.execute(
        "INSERT INTO comments"
        " (scope_kind, scope_id, author, author_user_id, body, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (scope_kind, scope_id, author, author_user_id, body, stamp, stamp),
    )
    conn.commit()
    return {
        "id": int(cur.lastrowid or 0),
        "scope_kind": scope_kind,
        "scope_id": scope_id,
        "author": author,
        "author_user_id": author_user_id,
        "body": body,
        "created_at": stamp,
        "updated_at": stamp,
    }


def list_comments(
    conn: sqlite3.Connection,
    *,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Comments, oldest first, optionally filtered by scope.

    ``visible_to`` drops comments on binaries (and on functions of binaries)
    the caller may not see, like the other scoped reads.
    """
    sql = "SELECT * FROM comments"
    clauses: list[str] = []
    params: list[Any] = []
    if scope_kind is not None:
        clauses.append("scope_kind = ?")
        params.append(scope_kind)
    if scope_id is not None:
        clauses.append("scope_id = ?")
        params.append(scope_id)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, scope_params = scope
        clauses.append(
            "((scope_kind = ? AND EXISTS (SELECT 1 FROM binaries b"
            f" WHERE b.id = comments.scope_id AND {clause}))"
            " OR (scope_kind = ? AND EXISTS (SELECT 1 FROM functions f"
            " JOIN analyses a ON f.analysis_id = a.id"
            " JOIN binaries b ON a.binary_id = b.id"
            f" WHERE f.id = comments.scope_id AND {clause})))"
        )
        params.extend(["binary", *scope_params, "function", *scope_params])
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    return _rows(conn.execute(sql, params))


def get_comment(conn: sqlite3.Connection, comment_id: int) -> dict[str, Any] | None:
    """One comment row by id, or None."""
    row = conn.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    return dict(row) if row else None


def update_comment(
    conn: sqlite3.Connection, comment_id: int, *, body: str
) -> dict[str, Any] | None:
    """Replace a comment's body and stamp ``updated_at``; None for an unknown id.

    Raises ValueError for a blank body.
    """
    if not body.strip():
        raise ValueError("comment body must not be empty")
    cur = conn.execute(
        "UPDATE comments SET body = ?, updated_at = ? WHERE id = ?",
        (body, now(), comment_id),
    )
    conn.commit()
    return get_comment(conn, comment_id) if cur.rowcount > 0 else None


def delete_comment(conn: sqlite3.Connection, comment_id: int) -> bool:
    """Delete one comment; False when the id is unknown."""
    cur = conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    return cur.rowcount > 0


# ── Binary deletion ────────────────────────────────────────────────


def delete_binary(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Delete a binary and everything scoped to it; None for an unknown id.

    Foreign keys cascade the analyses, functions, matches, scans,
    decompilations, rename history, tags, fingerprints, graph rows, data types
    and family rows.  Comments, conversations and documents carry a loose
    scope reference with no foreign key, so they are removed explicitly, both
    the binary-scoped rows and the function-scoped ones of its functions.
    Returns the deleted binary's counts.
    """
    binary = get_binary(conn, binary_id)
    if binary is None:
        return None
    function_scope = (
        "SELECT f.id FROM functions f JOIN analyses a ON f.analysis_id = a.id WHERE a.binary_id = ?"
    )
    function_count = len(_rows(conn.execute(function_scope, (binary_id,))))
    deleted = {
        "comments": 0,
        "conversations": 0,
        "documents": 0,
        "functions": function_count,
    }
    # The three table names are fixed; `functions` cascades through the schema.
    for kind in ("comments", "conversations", "documents"):
        cur = conn.execute(
            f"DELETE FROM {kind}"
            " WHERE (scope_kind = 'binary' AND scope_id = ?)"
            f" OR (scope_kind = 'function' AND scope_id IN ({function_scope}))",
            (binary_id, binary_id),
        )
        deleted[kind] = cur.rowcount
    conn.execute("DELETE FROM binaries WHERE id = ?", (binary_id,))
    conn.commit()
    return deleted


# ── Documents and chunks ───────────────────────────────────────────


def _embedding_vector(raw: Any) -> list[float] | None:
    """Parse a stored embedding column into a vector, or None when unusable."""
    if raw is None:
        return None
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not parsed:
        return None
    values: list[float] = []
    for entry in parsed:
        if isinstance(entry, bool) or not isinstance(entry, (int, float)):
            return None
        values.append(float(entry))
    return values


def _document_row(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """One ``documents`` row with its chunk count."""
    document = dict(row)
    count = conn.execute(
        "SELECT COUNT(*) FROM chunks WHERE document_id = ?", (document["id"],)
    ).fetchone()
    document["chunk_count"] = int(count[0]) if count else 0
    return document


def add_document(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    title: str,
    sha256: str,
    text: str,
    source: str = "",
    mime: str = "",
    size: int = 0,
    commit: bool = True,
) -> int:
    """Insert a document row; returns its id.

    The ``(scope_kind, scope_id, sha256)`` unique index is the dedupe key: the
    caller resolves an existing row through :func:`find_document_by_sha256`
    before inserting, so a repeated ingest never adds a second row.  Pass
    ``commit=False`` when the caller will commit the document and its chunks
    together.
    """
    cur = conn.execute(
        "INSERT INTO documents"
        " (scope_kind, scope_id, title, source, mime, sha256, size, text, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scope_kind, scope_id, title, source, mime, sha256, size, text, now()),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def find_document_by_sha256(
    conn: sqlite3.Connection, *, scope_kind: str, scope_id: int, sha256: str
) -> dict[str, Any] | None:
    """The document of that content hash inside a scope, or None.

    Ingest resolves dedupe with this, mirroring ``find_binary_by_sha256``: the
    same bytes in two scopes are two documents, and the same bytes twice in one
    scope are one.
    """
    row = conn.execute(
        "SELECT * FROM documents WHERE scope_kind = ? AND scope_id = ? AND sha256 = ?",
        (scope_kind, scope_id, sha256),
    ).fetchone()
    return _document_row(conn, row) if row else None


def get_document(conn: sqlite3.Connection, document_id: int) -> dict[str, Any] | None:
    """One document with its chunk count, or None."""
    row = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    return _document_row(conn, row) if row else None


def _document_where(
    conn: sqlite3.Connection,
    *,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> tuple[str, list[Any]]:
    """Shared WHERE clause for :func:`list_documents` and :func:`count_documents`."""
    clauses: list[str] = []
    params: list[Any] = []
    if scope_kind is not None:
        clauses.append("d.scope_kind = ?")
        params.append(scope_kind)
    if scope_id is not None:
        clauses.append("d.scope_id = ?")
        params.append(scope_id)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, scope_params = scope
        clauses.append(
            f"(d.scope_kind != ? OR EXISTS (SELECT 1 FROM binaries b"
            f" WHERE b.id = d.scope_id AND {clause}))"
        )
        params.extend(["binary", *scope_params])
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def list_documents(
    conn: sqlite3.Connection,
    *,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Documents (optionally scoped), newest id last, without their stored text.

    ``visible_to`` drops binary-scoped documents on binaries the caller may
    not see, like the other scoped reads; documents of other scopes (project,
    docs) have no owning binary and stay.
    """
    sql = (
        "SELECT d.id, d.scope_kind, d.scope_id, d.title, d.source, d.mime, d.sha256,"
        " d.size, d.created_at, ("
        "  SELECT COUNT(*) FROM chunks c WHERE c.document_id = d.id"
        ") AS chunk_count FROM documents d"
    )
    where, params = _document_where(
        conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=visible_to
    )
    sql += where
    sql += " ORDER BY d.id"
    return _rows(conn.execute(sql, params))


def count_documents(
    conn: sqlite3.Connection,
    *,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> int:
    """How many documents the same filters :func:`list_documents` takes keep."""
    where, params = _document_where(
        conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=visible_to
    )
    row = conn.execute("SELECT COUNT(*) AS total FROM documents d" + where, params).fetchone()
    return int(row["total"]) if row is not None else 0


def delete_document(conn: sqlite3.Connection, document_id: int) -> bool:
    """Delete a document and its chunks; False when the id is unknown.

    The ``ON DELETE CASCADE`` on ``chunks.document_id`` removes the chunks, so
    a deleted document leaves no orphan rows.
    """
    cur = conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    conn.commit()
    return cur.rowcount > 0


def add_chunk(
    conn: sqlite3.Connection,
    *,
    document_id: int,
    ordinal: int,
    text: str,
    embedding: Sequence[float] | None = None,
    commit: bool = True,
) -> int:
    """Append one chunk of a document; returns its id.

    ``embedding`` is stored as JSON, or NULL when the document was ingested
    without an embeddings endpoint, which leaves the chunk to the TF-IDF path.
    Pass ``commit=False`` when the caller will commit the document and its
    chunks together.
    """
    stored = json.dumps([float(value) for value in embedding]) if embedding else None
    cur = conn.execute(
        "INSERT INTO chunks (document_id, ordinal, text, embedding_json, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (document_id, ordinal, text, stored, now()),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid or 0)


def list_chunks(conn: sqlite3.Connection, document_id: int) -> list[dict[str, Any]]:
    """Chunks of a document in order, each with its text and an ``embedded`` flag."""
    cur = conn.execute(
        "SELECT id, document_id, ordinal, text, embedding_json, created_at FROM chunks"
        " WHERE document_id = ? ORDER BY ordinal, id",
        (document_id,),
    )
    return [
        {
            "id": int(row["id"]),
            "document_id": int(row["document_id"]),
            "ordinal": int(row["ordinal"]),
            "text": str(row["text"]),
            "created_at": str(row["created_at"]),
            "embedded": row["embedding_json"] is not None,
        }
        for row in cur.fetchall()
    ]


def iter_chunks_with_embeddings(
    conn: sqlite3.Connection, *, scope_kind: str | None = None, scope_id: int | None = None
) -> list[dict[str, Any]]:
    """Chunks (optionally scoped) with their document and parsed embedding.

    The row carries the chunk text as well as its vector, so the embedding
    ranking and the TF-IDF fallback read one query.  ``embedding`` is None for
    a chunk stored without one, and the document fields are the ones a search
    result reports.
    """
    sql = (
        "SELECT c.id, c.document_id, c.ordinal, c.text, c.embedding_json, c.created_at,"
        " d.title, d.source, d.scope_kind, d.scope_id"
        " FROM chunks c JOIN documents d ON c.document_id = d.id"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if scope_kind is not None:
        clauses.append("d.scope_kind = ?")
        params.append(scope_kind)
    if scope_id is not None:
        clauses.append("d.scope_id = ?")
        params.append(scope_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY c.document_id, c.ordinal, c.id"
    return [
        {
            "id": int(row["id"]),
            "document_id": int(row["document_id"]),
            "ordinal": int(row["ordinal"]),
            "text": str(row["text"]),
            "created_at": str(row["created_at"]),
            "embedding": _embedding_vector(row["embedding_json"]),
            "title": str(row["title"]),
            "source": str(row["source"]),
            "scope_kind": str(row["scope_kind"]),
            "scope_id": int(row["scope_id"]),
        }
        for row in conn.execute(sql, params).fetchall()
    ]


# ── Search and counts ──────────────────────────────────────────────

# Search query types.  ``all`` is the substring behaviour the route had before
# the types existed, so a caller that names none keeps every result it found
# and the typed queries are a superset rather than a replacement.
SEARCH_KIND_ALL = "all"
SEARCH_KIND_SHA256 = "sha256"
SEARCH_KIND_BINARY = "binary"
SEARCH_KIND_COLLECTION = "collection"
SEARCH_KIND_TAG = "tag"
SEARCH_KINDS: tuple[str, ...] = (
    SEARCH_KIND_ALL,
    SEARCH_KIND_SHA256,
    SEARCH_KIND_BINARY,
    SEARCH_KIND_COLLECTION,
    SEARCH_KIND_TAG,
)

# The result groups one search answers, in the order the SPA renders them.
SEARCH_GROUPS: tuple[str, ...] = ("binaries", "functions", "collections", "tags")

# Rows one group returns when the caller names no limit, and the hard cap.
DEFAULT_SEARCH_LIMIT = 50
MAX_SEARCH_LIMIT = 500

# Shortest SHA-256 prefix the hash query accepts.  A shorter hex string names
# too many candidates to be useful, so it is refused rather than answered with
# a guess; a full-length digest is always accepted.
MIN_SHA256_PREFIX = 8
SHA256_HEX_LENGTH = 64


class SearchError(ValueError):
    """A refused search query, carrying the stable code the route returns."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _search_counts(returned: int, total: int) -> dict[str, int]:
    """One group's returned-vs-matched counts, so a limit never reads as a total."""
    return {"count": returned, "total": total}


def _empty_search() -> dict[str, Any]:
    """Every group empty, so an empty query answers the same shape as a match."""
    return {
        **{group: [] for group in SEARCH_GROUPS},
        "counts": {group: _search_counts(0, 0) for group in SEARCH_GROUPS},
    }


def _count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> int:
    """The number of rows *sql* matches, ignoring its LIMIT."""
    row = conn.execute(f"SELECT COUNT(*) FROM ({sql})", params).fetchone()
    return int(row[0]) if row else 0


def _binary_match(row: Mapping[str, Any], needle: _Match) -> str:
    """Which field of a binary row the needle matched."""
    if needle.test(row.get("sha256")):
        return SEARCH_KIND_SHA256
    if needle.test(row.get("name")):
        return SEARCH_KIND_BINARY
    if needle.test(row.get("notes")):
        return "notes"
    return "path"


# Bounds for the opt-in regular-expression search.  A query is untrusted input,
# so a pattern is capped and its compiled form cached; Python's `re` cannot be
# interrupted once a match is running, so a pathological pattern costs what it
# costs (a stated ceiling, not a timeout this module can enforce).
MAX_REGEX_CHARS = 200
REGEX_CACHE_SIZE = 64
_REGEX_CACHE: OrderedDict[str, re.Pattern[str]] = OrderedDict()
_REGEX_CACHE_LOCK = threading.Lock()


class _Match:
    """One search needle: a literal substring or an opt-in regular expression.

    ``clause`` builds the SQL fragment and its parameter for one column, so a
    literal search keeps its escaped ``LIKE`` and a regex search swaps in the
    ``REGEXP`` function :func:`register_regexp` installs.  ``test`` answers the
    same question in Python for the row post-processing the helpers do (a tag
    already matched by SQL still needs its match kind labeled).
    """

    def __init__(self, query: str, *, regex: bool = False) -> None:
        self.regex = regex
        self.query = query
        self.literal = _escape_like(query)

    def clause(self, column: str) -> tuple[str, str]:
        """The SQL fragment and parameter that match *column*."""
        if self.regex:
            return f"{column} REGEXP ?", self.query
        return f"{column} LIKE ? ESCAPE '\\'", f"%{self.literal}%"

    def test(self, value: Any) -> bool:
        """True when *value* matches, for a row the SQL already selected."""
        text = str(value or "")
        if not text:
            return False
        if self.regex:
            return bool(compile_regex(self.query).search(text))
        return self.query.casefold() in text.casefold()


def compile_regex(pattern: str) -> re.Pattern[str]:
    """Compile one search pattern, capped and cached.

    Raises :class:`SearchError` with the ``invalid regex`` code for a pattern
    that is too long or does not compile, so the API answers 400 and the CLI,
    the MCP tool and the routes share one vocabulary.
    """
    if not pattern:
        raise SearchError("invalid regex", "a regular expression must not be empty")
    if len(pattern) > MAX_REGEX_CHARS:
        raise SearchError(
            "invalid regex", f"a regular expression is at most {MAX_REGEX_CHARS} characters"
        )
    with _REGEX_CACHE_LOCK:
        cached = _REGEX_CACHE.get(pattern)
        if cached is not None:
            _REGEX_CACHE.move_to_end(pattern)
            return cached
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise SearchError(
            "invalid regex", f"{pattern!r} is not a regular expression: {exc}"
        ) from None
    with _REGEX_CACHE_LOCK:
        existing = _REGEX_CACHE.get(pattern)
        if existing is not None:
            _REGEX_CACHE.move_to_end(pattern)
            return existing
        _REGEX_CACHE[pattern] = compiled
        while len(_REGEX_CACHE) > REGEX_CACHE_SIZE:
            _REGEX_CACHE.popitem(last=False)
    return compiled


def _regexp(pattern: Any, value: Any) -> int:
    """The SQL ``REGEXP`` function: 1 when *value* matches *pattern*, else 0."""
    if not isinstance(value, str) or not value:
        return 0
    try:
        compiled = compile_regex(str(pattern or ""))
    except SearchError:
        return 0
    return 1 if compiled.search(value) else 0


def register_regexp(conn: sqlite3.Connection) -> None:
    """Install the ``REGEXP`` function a regex query calls.

    SQLite has no regular-expression engine of its own, so one Python function
    is registered per connection.  It is deterministic, which is what lets
    SQLite treat it as a pure function for the query planner.
    """
    conn.create_function("regexp", 2, _regexp, deterministic=True)


def _binary_rows(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
    limit: int,
    needle: _Match,
    *,
    match: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Binary rows for *sql* plus the match kind that made each row hit."""
    total = _count(conn, sql, params)
    rows = _rows(conn.execute(f"{sql} LIMIT ?", (*params, limit)))
    tags = _tags_for_binaries(conn, [int(row["id"]) for row in rows])
    for row in rows:
        row["tags"] = tags.get(int(row["id"]), [])
        row["match"] = match or _binary_match(row, needle)
        # A hand-set override answers reads first, like every other surface.
        if "format_override" in row:
            row["format"] = effective_format(row)
        if "arch_override" in row:
            row["arch"] = effective_arch(row)
    return rows, total


def _binary_columns(conn: sqlite3.Connection) -> str:
    """The binary columns a search row carries, plus overrides when migrated.

    An old database opened without the upgrade lacks the override columns;
    naming them unconditionally would break its reads, so they join the list
    only when the table has them (the same guard the history readers use).
    """
    columns = "id, name, sha256, size, format, arch, created_at, path, notes"
    existing = {str(row["name"]) for row in conn.execute("PRAGMA table_info(binaries)")}
    if "format_override" in existing:
        columns += ", format_override, arch_override"
    return columns


def _search_binaries(
    conn: sqlite3.Connection, match: _Match, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Binaries whose name, path, hash or notes carry the needle (the default search)."""
    name_sql, name_param = match.clause("name")
    path_sql, path_param = match.clause("path")
    hash_sql, hash_param = match.clause("sha256")
    notes_sql, notes_param = match.clause("notes")
    sql = (
        f"SELECT {_binary_columns(conn)} FROM binaries"
        f" WHERE {name_sql} OR {path_sql} OR {hash_sql} OR {notes_sql} ORDER BY id"
    )
    return _binary_rows(conn, sql, (name_param, path_param, hash_param, notes_param), limit, match)


def _search_sha256(
    conn: sqlite3.Connection, query: str, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Binaries whose sha256 starts with *query*, refusing an ambiguous prefix."""
    value = query.strip().lower()
    if len(value) > SHA256_HEX_LENGTH:
        raise SearchError(
            "invalid-hash",
            f"a SHA-256 is {SHA256_HEX_LENGTH} hex characters; the query is longer",
        )
    try:
        int(value, 16)
    except ValueError:
        raise SearchError("invalid-hash", f"{query!r} is not a hexadecimal SHA-256") from None
    if len(value) < MIN_SHA256_PREFIX:
        raise SearchError(
            "short-hash",
            f"a SHA-256 prefix must be at least {MIN_SHA256_PREFIX} hex characters",
        )
    sql = (
        f"SELECT {_binary_columns(conn)} FROM binaries WHERE sha256 LIKE ? ESCAPE '\\' ORDER BY id"
    )
    pattern = f"{value}%"
    total = _count(conn, sql, (pattern,))
    if total > 1 and len(value) < SHA256_HEX_LENGTH:
        raise SearchError(
            "ambiguous-hash",
            f"the prefix {value} matches {total} binaries; use a longer prefix",
        )
    rows, _ = _binary_rows(conn, sql, (pattern,), limit, _Match(value))
    return rows, total


def _search_binary_names(
    conn: sqlite3.Connection, match: _Match, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Binaries whose name carries the needle."""
    name_sql, name_param = match.clause("name")
    sql = f"SELECT {_binary_columns(conn)} FROM binaries WHERE {name_sql} ORDER BY id"
    return _binary_rows(conn, sql, (name_param,), limit, match)


def _search_binaries_by_tag(
    conn: sqlite3.Connection, match: _Match, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Binaries carrying a tag whose name carries the needle."""
    tag_sql, tag_param = match.clause("t.name")
    sql = (
        f"SELECT {_binary_columns(conn)} FROM binaries WHERE id IN ("
        " SELECT bt.binary_id FROM binary_tags bt JOIN tags t ON t.id = bt.tag_id"
        f" WHERE {tag_sql}) ORDER BY id"
    )
    return _binary_rows(conn, sql, (tag_param,), limit, match, match=SEARCH_KIND_TAG)


def _search_functions(
    conn: sqlite3.Connection, match: _Match, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Functions whose name carries the needle."""
    name_sql, name_param = match.clause("f.name")
    sql = (
        "SELECT f.id, f.va, f.name, f.status, a.binary_id AS binary_id"
        " FROM functions f JOIN analyses a ON f.analysis_id = a.id"
        f" WHERE {name_sql} ORDER BY f.va"
    )
    total = _count(conn, sql, (name_param,))
    rows = _rows(conn.execute(f"{sql} LIMIT ?", (name_param, limit)))
    for row in rows:
        row["match"] = "name"
    return rows, total


def _search_collections(
    conn: sqlite3.Connection, match: _Match, limit: int, *, names_only: bool
) -> tuple[list[dict[str, Any]], int]:
    """Collections whose name carries the needle, or whose description does too."""
    name_sql, name_param = match.clause("c.name")
    columns = (
        "SELECT c.id, c.name, c.description, c.created_at, c.visibility, ("
        " SELECT COUNT(*) FROM collection_binaries cb WHERE cb.collection_id = c.id"
        " ) AS binary_count FROM collections c WHERE " + name_sql
    )
    params: tuple[Any, ...] = (name_param,)
    if not names_only:
        description_sql, description_param = match.clause("c.description")
        columns += f" OR {description_sql}"
        params = (name_param, description_param)
    sql = f"{columns} ORDER BY c.id"
    total = _count(conn, sql, params)
    rows = _rows(conn.execute(f"{sql} LIMIT ?", (*params, limit)))
    for row in rows:
        row["match"] = "name" if match.test(row["name"]) else "description"
    return rows, total


def _search_tags(
    conn: sqlite3.Connection, match: _Match, limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Tags whose name carries the needle, with their tagged-binary count."""
    name_sql, name_param = match.clause("t.name")
    sql = (
        "SELECT t.id, t.name, ("
        " SELECT COUNT(*) FROM binary_tags bt WHERE bt.tag_id = t.id"
        f" ) AS binary_count FROM tags t WHERE {name_sql} ORDER BY t.name"
    )
    total = _count(conn, sql, (name_param,))
    rows = _rows(conn.execute(f"{sql} LIMIT ?", (name_param, limit)))
    for row in rows:
        row["match"] = "name"
    return rows, total


def search(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = DEFAULT_SEARCH_LIMIT,
    kind: str = SEARCH_KIND_ALL,
    visible_to: Mapping[str, Any] | None = None,
    regex: bool = False,
) -> dict[str, Any]:
    """Search the store by substring or by one typed query.

    ``kind`` is one of :data:`SEARCH_KINDS`: ``all`` (the default) matches
    binaries by name, path, hash or notes, functions by name, collections by
    name or description and tags by name; ``sha256`` matches a binary hash
    prefix, ``binary`` a binary name, ``collection`` a collection name and
    ``tag`` a tag name.  The typed forms are a subset of ``all`` for the same
    string, so nothing the route returned before is lost.

    Returns ``{"binaries", "functions", "collections", "tags", "counts"}``;
    each ``counts`` entry is the returned count against the matched total, so
    a limit never reads as a total.  LIKE wildcards in *query* are escaped so a
    literal ``%`` matches a percent sign rather than every row.  A query the
    typed form refuses raises :class:`SearchError`.

    ``regex=True`` matches *query* as a regular expression instead of a
    substring: the pattern is compiled once (bounded by
    :data:`MAX_REGEX_CHARS` and cached), a pattern that does not compile raises
    ``SearchError("invalid regex", ...)``, and the ``sha256`` kind is refused
    because a hash prefix is a literal by definition.
    """
    if kind not in SEARCH_KINDS:
        raise SearchError("invalid-kind", f"unknown search kind {kind!r}")
    if limit < 1:
        raise SearchError("invalid-limit", "limit must be a positive integer")
    limit = min(limit, MAX_SEARCH_LIMIT)
    query = query.strip()
    if not query:
        return _empty_search()
    if regex:
        if kind == SEARCH_KIND_SHA256:
            raise SearchError(
                "invalid regex", "the sha256 kind matches a literal hash prefix, not a pattern"
            )
        compile_regex(query)
        register_regexp(conn)
    needle = _Match(query, regex=regex)

    binaries: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    collections: list[dict[str, Any]] = []
    tags: list[dict[str, Any]] = []
    binary_total = function_total = collection_total = tag_total = 0

    if kind == SEARCH_KIND_SHA256:
        binaries, binary_total = _search_sha256(conn, query, limit)
    elif kind == SEARCH_KIND_BINARY:
        binaries, binary_total = _search_binary_names(conn, needle, limit)
    elif kind == SEARCH_KIND_COLLECTION:
        collections, collection_total = _search_collections(conn, needle, limit, names_only=True)
    elif kind == SEARCH_KIND_TAG:
        tags, tag_total = _search_tags(conn, needle, limit)
        binaries, binary_total = _search_binaries_by_tag(conn, needle, limit)
    else:
        binaries, binary_total = _search_binaries(conn, needle, limit)
        functions, function_total = _search_functions(conn, needle, limit)
        collections, collection_total = _search_collections(conn, needle, limit, names_only=False)
        tags, tag_total = _search_tags(conn, needle, limit)

    # The page is bounded, so the visibility filter runs over the returned rows:
    # a binary or collection in a team the caller is not in drops out of the
    # page, as do that binary's functions.  The *total* stays the unfiltered
    # match count, which is a stated residual (docs/THREAT_MODEL.md) rather
    # than a wrong page.
    scope = auth.visible_clause(conn, visible_to)
    if scope is not None:
        visible_ids = {
            int(row["id"])
            for row in conn.execute(f"SELECT id FROM binaries WHERE {scope[0]}", scope[1])
        }
        binaries = [row for row in binaries if int(row["id"]) in visible_ids]
        functions = [row for row in functions if int(row["binary_id"]) in visible_ids]
    collection_scope = auth.visible_clause(conn, visible_to, prefix="c.")
    if collection_scope is not None:
        visible_collection_ids = {
            int(row["id"])
            for row in conn.execute(
                f"SELECT c.id FROM collections c WHERE {collection_scope[0]}",
                collection_scope[1],
            )
        }
        collections = [row for row in collections if int(row["id"]) in visible_collection_ids]

    return {
        "binaries": binaries,
        "functions": functions,
        "collections": collections,
        "tags": tags,
        "counts": {
            "binaries": _search_counts(len(binaries), binary_total),
            "functions": _search_counts(len(functions), function_total),
            "collections": _search_counts(len(collections), collection_total),
            "tags": _search_counts(len(tags), tag_total),
        },
    }


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Row counts for the health endpoint and ``reportal stats``."""

    def scalar(sql: str, params: tuple[Any, ...] = ()) -> int:
        row = conn.execute(sql, params).fetchone()
        return int(row[0]) if row else 0

    placeholders = ", ".join("?" for _ in MATCHED_STATUSES)
    return {
        "binaries": scalar("SELECT COUNT(*) FROM binaries"),
        "analyses": scalar("SELECT COUNT(*) FROM analyses"),
        "functions": scalar("SELECT COUNT(*) FROM functions"),
        "matched": scalar(
            f"SELECT COUNT(*) FROM functions WHERE status IN ({placeholders})",
            tuple(sorted(MATCHED_STATUSES)),
        ),
        "matches": scalar("SELECT COUNT(*) FROM matches"),
        "comments": scalar("SELECT COUNT(*) FROM comments"),
        "collections": scalar("SELECT COUNT(*) FROM collections"),
        "families": scalar("SELECT COUNT(*) FROM families"),
        "documents": scalar("SELECT COUNT(*) FROM documents"),
        "chunks": scalar("SELECT COUNT(*) FROM chunks"),
    }


# ── Knowledge graph ────────────────────────────────────────────────


def _json_dict(raw: Any) -> dict[str, Any]:
    """Parse a JSON object column, returning {} when it is unusable."""
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


_GRAPH_NODE_FIELDS: tuple[_RowField, ...] = (
    ("id", "id", str),
    ("binary_id", "binary_id", int),
    ("kind", "kind", str),
    ("key", "key", str),
    ("label", "label", str),
    ("meta", "meta_json", _json_dict),
)


def _graph_node_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``graph_nodes`` row with its metadata parsed."""
    return _map_row(row, _GRAPH_NODE_FIELDS)


_GRAPH_EDGE_FIELDS: tuple[_RowField, ...] = (
    ("id", "id", str),
    ("binary_id", "binary_id", int),
    ("source", "source", str),
    ("target", "target", str),
    ("rel", "rel", str),
    ("weight", "weight", float),
    ("meta", "meta_json", _json_dict),
)


def _graph_edge_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``graph_edges`` row with its metadata parsed."""
    return _map_row(row, _GRAPH_EDGE_FIELDS)


_NODE_COLUMNS = 'id, binary_id, kind, "key", label, meta_json'
_EDGE_COLUMNS = "id, binary_id, source, target, rel, weight, meta_json"

# Escape character a graph-node text search uses, so a query carrying `%` or
# `_` matches those characters literally instead of as LIKE wildcards.
_LIKE_ESCAPE = "\\"


def add_graph_node(
    conn: sqlite3.Connection,
    *,
    node_id: str,
    binary_id: int,
    kind: str,
    key: str,
    label: str = "",
    meta: dict[str, Any] | None = None,
) -> None:
    """Insert or replace one graph node, keyed by its id."""
    conn.execute(
        f"INSERT INTO graph_nodes ({_NODE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET binary_id = excluded.binary_id, kind = excluded.kind,"
        ' "key" = excluded."key", label = excluded.label, meta_json = excluded.meta_json',
        (node_id, binary_id, kind, key, label, json.dumps(meta or {})),
    )
    conn.commit()


def add_graph_edge(
    conn: sqlite3.Connection,
    *,
    edge_id: str,
    binary_id: int,
    source: str,
    target: str,
    rel: str,
    weight: float = 1.0,
    meta: dict[str, Any] | None = None,
) -> None:
    """Insert or replace one directed graph edge, keyed by its id."""
    conn.execute(
        f"INSERT INTO graph_edges ({_EDGE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET binary_id = excluded.binary_id,"
        " source = excluded.source, target = excluded.target, rel = excluded.rel,"
        " weight = excluded.weight, meta_json = excluded.meta_json",
        (edge_id, binary_id, source, target, rel, weight, json.dumps(meta or {})),
    )
    conn.commit()


def list_graph_nodes(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Nodes of one binary's graph, ordered by kind, label and id."""
    cur = conn.execute(
        f"SELECT {_NODE_COLUMNS} FROM graph_nodes WHERE binary_id = ? ORDER BY kind, label, id",
        (binary_id,),
    )
    return [_graph_node_row(row) for row in cur.fetchall()]


def get_graph_node(conn: sqlite3.Connection, node_id: str) -> dict[str, Any] | None:
    """One graph node by id, or None.

    A node id embeds its binary id, so it is unique across graphs.
    """
    row = conn.execute(
        f"SELECT {_NODE_COLUMNS} FROM graph_nodes WHERE id = ?", (node_id,)
    ).fetchone()
    return _graph_node_row(row) if row else None


def search_graph_nodes(
    conn: sqlite3.Connection, *, needle: str, limit: int
) -> list[dict[str, Any]]:
    """Nodes whose id, label or key contains *needle*, across every binary.

    Ordered by kind, label and id, and capped at *limit*.  A `%` or `_` in
    *needle* matches literally, so a query never turns into a wildcard.
    """
    escaped = needle.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
    escaped = escaped.replace("%", f"{_LIKE_ESCAPE}%").replace("_", f"{_LIKE_ESCAPE}_")
    pattern = f"%{escaped}%"
    cur = conn.execute(
        f"SELECT {_NODE_COLUMNS} FROM graph_nodes"
        " WHERE id LIKE ? ESCAPE '\\' OR label LIKE ? ESCAPE '\\'"
        " OR \"key\" LIKE ? ESCAPE '\\' ORDER BY kind, label, id LIMIT ?",
        (pattern, pattern, pattern, limit),
    )
    return [_graph_node_row(row) for row in cur.fetchall()]


def list_graph_edges(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Edges of one binary's graph, ordered by id."""
    cur = conn.execute(
        f"SELECT {_EDGE_COLUMNS} FROM graph_edges WHERE binary_id = ? ORDER BY id",
        (binary_id,),
    )
    return [_graph_edge_row(row) for row in cur.fetchall()]


def list_graph_edges_for_node(conn: sqlite3.Connection, node_id: str) -> list[dict[str, Any]]:
    """Every edge with *node_id* at either end, ordered by id."""
    cur = conn.execute(
        f"SELECT {_EDGE_COLUMNS} FROM graph_edges WHERE source = ? OR target = ? ORDER BY id",
        (node_id, node_id),
    )
    return [_graph_edge_row(row) for row in cur.fetchall()]


def count_graph_edges_for_node(conn: sqlite3.Connection, node_id: str) -> int:
    """How many edges touch *node_id* at either end."""
    row = conn.execute(
        "SELECT COUNT(*) AS total FROM graph_edges WHERE source = ? OR target = ?",
        (node_id, node_id),
    ).fetchone()
    return int(row["total"]) if row is not None else 0


def count_graph_nodes(conn: sqlite3.Connection, binary_id: int) -> int:
    """Number of stored nodes in one binary's graph."""
    row = conn.execute(
        "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ?", (binary_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def count_graph_edges(conn: sqlite3.Connection, binary_id: int) -> int:
    """Number of stored edges in one binary's graph."""
    row = conn.execute(
        "SELECT COUNT(*) FROM graph_edges WHERE binary_id = ?", (binary_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def delete_graph(conn: sqlite3.Connection, binary_id: int) -> int:
    """Delete one binary's graph; returns the rows removed.

    A rebuild starts here, so a node or edge the previous build wrote and the
    new one no longer derives cannot survive.
    """
    edges = conn.execute("DELETE FROM graph_edges WHERE binary_id = ?", (binary_id,)).rowcount
    nodes = conn.execute("DELETE FROM graph_nodes WHERE binary_id = ?", (binary_id,)).rowcount
    conn.commit()
    return int(edges) + int(nodes)


# ── Data types ─────────────────────────────────────────────────────

# Columns of a `data_types` row, in row order.
_DATA_TYPE_COLUMNS = (
    "id, binary_id, name, kind, namespace, size, members_json, values_json,"
    " target, element_count, source, created_at, updated_at"
)


def _optional_int(value: Any) -> int | None:
    """int(*value*), or None when the column is NULL."""
    return None if value is None else int(value)


_DATA_TYPE_FIELDS: tuple[_RowField, ...] = (
    ("id", "id", int),
    ("binary_id", "binary_id", int),
    ("name", "name", str),
    ("kind", "kind", str),
    ("namespace", "namespace", str),
    ("size", "size", int),
    ("members", "members_json", _json_list),
    ("values", "values_json", _json_list),
    ("target", "target", str),
    ("element_count", "element_count", _optional_int),
    ("source", "source", str),
    ("created_at", "created_at", str),
    ("updated_at", "updated_at", str),
)


def _data_type_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``data_types`` row with its members and enum values parsed from JSON."""
    return _map_row(row, _DATA_TYPE_FIELDS)


def add_data_type(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    name: str,
    size: int,
    members: Sequence[dict[str, Any]],
    kind: str = "struct",
    namespace: str = "",
    values: Sequence[dict[str, Any]] = (),
    target: str = "",
    element_count: int | None = None,
    source: str = "",
) -> int:
    """Insert one data type, returning its id.

    ``kind`` defaults to ``struct`` because that is the only shape the stored
    structs scan ever emits; another kind is passed explicitly by the parser or
    a caller building the row by hand.
    """
    stamp = now()
    cur = conn.execute(
        "INSERT INTO data_types (binary_id, name, kind, namespace, size, members_json,"
        " values_json, target, element_count, source, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            binary_id,
            name,
            kind,
            namespace,
            size,
            json.dumps(list(members)),
            json.dumps(list(values)),
            target,
            element_count,
            source,
            stamp,
            stamp,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_data_types(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Data types of one binary, ordered by name."""
    cur = conn.execute(
        f"SELECT {_DATA_TYPE_COLUMNS} FROM data_types WHERE binary_id = ? ORDER BY name",
        (binary_id,),
    )
    return [_data_type_row(row) for row in cur.fetchall()]


def get_data_type(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any] | None:
    """One data type by id, or None."""
    row = conn.execute(
        f"SELECT {_DATA_TYPE_COLUMNS} FROM data_types WHERE id = ?", (data_type_id,)
    ).fetchone()
    return _data_type_row(row) if row else None


def find_data_type_by_name(
    conn: sqlite3.Connection, binary_id: int, name: str
) -> dict[str, Any] | None:
    """One data type by its unique ``(binary_id, name)`` key, or None."""
    row = conn.execute(
        f"SELECT {_DATA_TYPE_COLUMNS} FROM data_types WHERE binary_id = ? AND name = ?",
        (binary_id, name),
    ).fetchone()
    return _data_type_row(row) if row else None


def data_type_ids_by_name(conn: sqlite3.Connection, binary_id: int) -> dict[str, int]:
    """Map each data-type name of *binary_id* to its id, in one round trip.

    A symbol-file or bulk import that resolves many names used to query once
    per name; this index keeps those paths from paying a lookup per type.
    """
    return {
        str(row["name"]): int(row["id"])
        for row in conn.execute(
            "SELECT id, name FROM data_types WHERE binary_id = ?",
            (binary_id,),
        )
    }


def update_data_type(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    kind: str | None = None,
    namespace: str | None = None,
    size: int | None = None,
    members: Sequence[dict[str, Any]] | None = None,
    values: Sequence[dict[str, Any]] | None = None,
    target: str | None = None,
    element_count: int | None = None,
    source: str | None = None,
) -> None:
    """Update the fields the caller names, stamping ``updated_at``.

    ``None`` means "leave alone" for every field, so a caller that clears a
    value passes the empty string; ``element_count`` is only ever set by an
    array type, which always carries a count.
    """
    assignments = ["updated_at = ?"]
    fields: list[Any] = [now()]
    if name is not None:
        assignments.append("name = ?")
        fields.append(name)
    if kind is not None:
        assignments.append("kind = ?")
        fields.append(kind)
    if namespace is not None:
        assignments.append("namespace = ?")
        fields.append(namespace)
    if size is not None:
        assignments.append("size = ?")
        fields.append(size)
    if members is not None:
        assignments.append("members_json = ?")
        fields.append(json.dumps(list(members)))
    if values is not None:
        assignments.append("values_json = ?")
        fields.append(json.dumps(list(values)))
    if target is not None:
        assignments.append("target = ?")
        fields.append(target)
    if element_count is not None:
        assignments.append("element_count = ?")
        fields.append(element_count)
    if source is not None:
        assignments.append("source = ?")
        fields.append(source)
    fields.append(data_type_id)
    conn.execute(f"UPDATE data_types SET {', '.join(assignments)} WHERE id = ?", tuple(fields))
    conn.commit()


def delete_data_type(conn: sqlite3.Connection, data_type_id: int) -> bool:
    """Delete one data type; False for an unknown id."""
    cur = conn.execute("DELETE FROM data_types WHERE id = ?", (data_type_id,))
    conn.commit()
    return cur.rowcount > 0


def restore_data_type(
    conn: sqlite3.Connection,
    *,
    data_type_id: int,
    binary_id: int,
    name: str,
    kind: str,
    namespace: str,
    size: int,
    members: Sequence[dict[str, Any]],
    values: Sequence[dict[str, Any]],
    target: str,
    element_count: int | None,
    source: str,
) -> None:
    """Write one data type back under its original id, restoring a deleted row.

    The id is explicit because a history entry records the row it replaced and
    the type column is ``AUTOINCREMENT``, so an id is never reused by a later
    create.  A row still present is updated in place (its ``created_at`` is
    kept); a deleted one is re-inserted.  A ``(binary_id, name)`` clash with
    another row is left to SQLite: the caller checks the name first so the
    failure is a domain error rather than an integrity traceback.
    """
    stamp = now()
    conn.execute(
        "INSERT INTO data_types (id, binary_id, name, kind, namespace, size, members_json,"
        " values_json, target, element_count, source, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,"
        " namespace = excluded.namespace, size = excluded.size,"
        " members_json = excluded.members_json, values_json = excluded.values_json,"
        " target = excluded.target, element_count = excluded.element_count,"
        " source = excluded.source, updated_at = excluded.updated_at",
        (
            data_type_id,
            binary_id,
            name,
            kind,
            namespace,
            size,
            json.dumps(list(members)),
            json.dumps(list(values)),
            target,
            element_count,
            source,
            stamp,
            stamp,
        ),
    )
    conn.commit()


# ── Data-type history ──────────────────────────────────────────────


def ensure_data_type_history(conn: sqlite3.Connection) -> None:
    """Create the data-type history table when the database predates it.

    ``init_db`` creates it through :data:`_SCHEMA`, but a workspace whose
    database was written before this table existed never re-runs that script,
    so the readers and writers below create it on first use the way the journal
    and the analysis log do with their own tables.
    """
    conn.executescript(_DATA_TYPE_HISTORY_DDL)
    conn.commit()


def history_actor_names(
    conn: sqlite3.Connection, entries: Sequence[Mapping[str, Any]]
) -> dict[int, str]:
    """Display names for the user ids history entries point at, keyed by id.

    A missing user row maps to no name, and the entry keeps its stored
    ``actor`` login name.  Deleted users clear ``actor_user_id`` here, so in
    practice this answers the users that still exist.
    """
    ids = {
        int(entry["actor_user_id"]) for entry in entries if entry.get("actor_user_id") is not None
    }
    names: dict[int, str] = {}
    for user_id in ids:
        user = auth.get_user(conn, user_id)
        if user is not None:
            names[user_id] = str(user["name"])
    return names


def _data_type_history_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``data_type_history`` row with both recorded states parsed from JSON."""
    previous = json.loads(row["previous_json"])
    current = json.loads(row["current_json"])
    columns = set(row.keys())
    raw_id = row["actor_user_id"] if "actor_user_id" in columns else None
    return {
        "id": int(row["id"]),
        "data_type_id": int(row["data_type_id"]),
        "binary_id": int(row["binary_id"]),
        "previous": previous if isinstance(previous, dict) else None,
        "current": current if isinstance(current, dict) else None,
        "source": str(row["source"] or ""),
        "actor": str(row["actor"] or ""),
        "actor_user_id": None if raw_id is None else int(raw_id),
        "created_at": str(row["created_at"] or ""),
    }


def add_data_type_history(
    conn: sqlite3.Connection,
    *,
    data_type_id: int,
    binary_id: int,
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any] | None,
    source: str = "",
    actor: str = "",
    actor_user_id: int | None = None,
) -> int:
    """Append one history row recording the states a write replaced and wrote.

    Either side is None: *previous* when the write created the type, *current*
    when the write deleted it.  Returns the new row's id.  The row carries no
    foreign key to ``data_types``, so a deleted type's history stays readable
    and revertible; it does cascade with the binary, whose delete removes every
    row scoped to it anyway.
    """
    ensure_data_type_history(conn)
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(data_type_history)")}
    if "actor_user_id" in columns:
        cur = conn.execute(
            "INSERT INTO data_type_history"
            " (data_type_id, binary_id, previous_json, current_json, source, actor,"
            " actor_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                data_type_id,
                binary_id,
                json.dumps(previous),
                json.dumps(current),
                source,
                actor,
                actor_user_id,
                now(),
            ),
        )
    else:
        cur = conn.execute(
            "INSERT INTO data_type_history"
            " (data_type_id, binary_id, previous_json, current_json, source, actor, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                data_type_id,
                binary_id,
                json.dumps(previous),
                json.dumps(current),
                source,
                actor,
                now(),
            ),
        )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_data_type_history(conn: sqlite3.Connection, data_type_id: int) -> list[dict[str, Any]]:
    """One type's edit history, newest first, whatever became of the row."""
    ensure_data_type_history(conn)
    cur = conn.execute(
        "SELECT * FROM data_type_history WHERE data_type_id = ? ORDER BY id DESC",
        (data_type_id,),
    )
    return [_data_type_history_row(row) for row in cur.fetchall()]


def get_data_type_history(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One data-type-history row by id, or None."""
    ensure_data_type_history(conn)
    row = conn.execute("SELECT * FROM data_type_history WHERE id = ?", (history_id,)).fetchone()
    return _data_type_history_row(row) if row else None


# ── Function signatures ────────────────────────────────────────────


def _or_empty(value: Any) -> str:
    """str(*value*), treating NULL as the empty string."""
    return str(value or "")


_FUNCTION_SIGNATURE_FIELDS: tuple[_RowField, ...] = (
    ("function_id", "function_id", int),
    ("name", "name", _or_empty),
    ("return_type", "return_type", _or_empty),
    ("calling_convention", "calling_convention", _or_empty),
    ("parameters", "parameters_json", _json_list),
    ("source", "source", _or_empty),
    ("created_at", "created_at", _or_empty),
    ("updated_at", "updated_at", _or_empty),
)


def _function_signature_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``function_signatures`` row with its parameters parsed from JSON."""
    return _map_row(row, _FUNCTION_SIGNATURE_FIELDS)


def upsert_signature(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    name: str,
    return_type: str,
    calling_convention: str,
    parameters: Sequence[dict[str, Any]],
    source: str = "",
) -> None:
    """Insert or replace the signature of *function_id*, keyed by its id."""
    stamp = now()
    conn.execute(
        "INSERT INTO function_signatures (function_id, name, return_type, calling_convention,"
        " parameters_json, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(function_id) DO UPDATE SET name = excluded.name,"
        " return_type = excluded.return_type,"
        " calling_convention = excluded.calling_convention,"
        " parameters_json = excluded.parameters_json, source = excluded.source,"
        " updated_at = excluded.updated_at",
        (
            function_id,
            name,
            return_type,
            calling_convention,
            json.dumps(list(parameters)),
            source,
            stamp,
            stamp,
        ),
    )
    conn.commit()


def get_signature(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """One function signature by its function id, or None."""
    return signatures_by_ids(conn, [function_id]).get(int(function_id))


def signatures_by_ids(
    conn: sqlite3.Connection, function_ids: Sequence[int]
) -> dict[int, dict[str, Any]]:
    """Signatures keyed by function id for the ids that have one.

    One round trip for a batch read; an unknown or unsigned id is absent.
    """
    if not function_ids:
        return {}
    ids = [int(function_id) for function_id in function_ids]
    placeholders = ", ".join("?" for _ in ids)
    cur = conn.execute(
        "SELECT function_id, name, return_type, calling_convention, parameters_json,"
        " source, created_at, updated_at FROM function_signatures"
        f" WHERE function_id IN ({placeholders})",
        ids,
    )
    return {int(row["function_id"]): _function_signature_row(row) for row in cur.fetchall()}


def list_signatures(conn: sqlite3.Connection, *, binary_id: int) -> list[dict[str, Any]]:
    """Signatures of one binary's functions, ordered by name then function id."""
    cur = conn.execute(
        "SELECT s.function_id AS function_id, s.name AS name, s.return_type AS return_type,"
        " s.calling_convention AS calling_convention, s.parameters_json AS parameters_json,"
        " s.source AS source, s.created_at AS created_at, s.updated_at AS updated_at"
        " FROM function_signatures s JOIN functions f ON s.function_id = f.id"
        " JOIN analyses a ON f.analysis_id = a.id"
        " WHERE a.binary_id = ? ORDER BY s.name, s.function_id",
        (binary_id,),
    )
    return [_function_signature_row(row) for row in cur.fetchall()]


def delete_signature(conn: sqlite3.Connection, function_id: int) -> bool:
    """Delete one signature; False for an unknown function id."""
    cur = conn.execute("DELETE FROM function_signatures WHERE function_id = ?", (function_id,))
    conn.commit()
    return cur.rowcount > 0


# ── Signature history ──────────────────────────────────────────────


def _signature_history_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``signature_history`` row with its previous state parsed from JSON."""
    previous = json.loads(row["previous_json"])
    columns = set(row.keys())
    raw_id = row["actor_user_id"] if "actor_user_id" in columns else None
    return {
        "id": int(row["id"]),
        "function_id": int(row["function_id"]),
        "previous": previous if isinstance(previous, dict) else None,
        "source": str(row["source"] or ""),
        "actor": str(row["actor"] or ""),
        "actor_user_id": None if raw_id is None else int(raw_id),
        "created_at": str(row["created_at"] or ""),
    }


def add_signature_history(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    previous: Mapping[str, Any] | None,
    source: str = "",
    actor: str = "",
    actor_user_id: int | None = None,
) -> int:
    """Append one signature-history row recording the state a write replaced.

    *previous* is the signature row before the write, or None when the write
    created it.  Returns the new row's id.
    """
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(signature_history)")}
    if "actor_user_id" in columns:
        cur = conn.execute(
            "INSERT INTO signature_history"
            " (function_id, previous_json, source, actor, actor_user_id, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (function_id, json.dumps(previous), source, actor, actor_user_id, now()),
        )
    else:
        cur = conn.execute(
            "INSERT INTO signature_history (function_id, previous_json, source, actor, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (function_id, json.dumps(previous), source, actor, now()),
        )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_signature_history(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """Signature history of a function, newest first."""
    cur = conn.execute(
        "SELECT * FROM signature_history WHERE function_id = ? ORDER BY id DESC",
        (function_id,),
    )
    return [_signature_history_row(row) for row in cur.fetchall()]


def get_signature_history(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One signature-history row by id, or None."""
    row = conn.execute("SELECT * FROM signature_history WHERE id = ?", (history_id,)).fetchone()
    return _signature_history_row(row) if row else None


# ── Per-section byte coverage ──────────────────────────────────────


def _percent(covered: int, total: int) -> float | None:
    """*covered* as a percentage of *total*, or None when *total* is zero."""
    if total <= 0:
        return None
    return round(100 * covered / total, COVERAGE_PERCENT_DIGITS)


def _merge_intervals(intervals: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping or touching half-open intervals, sorted by start."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            continue
        merged.append((start, end))
    return merged


def section_byte_coverage(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Per-section byte coverage over the stored ``pe-info`` sections and functions.

    Returns None when the binary has no stored ``pe-info`` scan, which is what
    the route turns into a 404 ``no-scan``.  A stored function contributes its
    extent only to the section its VA falls inside, clipped at the section end;
    the covered bytes are the union of those intervals, so overlapping
    functions never double count.  Percentages are None when a section has no
    bytes or the binary has no stored functions, never a fabricated 0.
    """
    analysis_id = latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    stored = get_scan(conn, analysis_id, SCAN_KIND_PE_INFO)
    if stored is None:
        return None
    image_base = int(stored.get("image_base") or 0)
    sections = [entry for entry in stored.get("sections") or [] if isinstance(entry, Mapping)]
    function_extents = [
        (int(row["va"]), int(row["size"]))
        for row in conn.execute(
            "SELECT f.va AS va, f.size AS size FROM functions f"
            " JOIN analyses a ON f.analysis_id = a.id WHERE a.binary_id = ?",
            (binary_id,),
        )
    ]
    zero_functions = not function_extents

    entries: list[dict[str, Any]] = []
    total_bytes = 0
    total_covered = 0
    for section in sections:
        start = image_base + int(section.get("virtual_address") or 0)
        size = int(section.get("virtual_size") or 0)
        end = start + size
        intervals = [
            (max(va, start), min(va + extent, end))
            for va, extent in function_extents
            if start <= va < end
        ]
        covered = sum(stop - begin for begin, stop in _merge_intervals(intervals))
        total_bytes += size
        total_covered += covered
        entries.append(
            {
                "name": str(section.get("name") or ""),
                "va": start,
                "size": size,
                "covered": covered,
                "uncovered": size - covered,
                "coverage_pct": None if zero_functions else _percent(covered, size),
            }
        )
    note = FUNCTION_COVERAGE_NOTE
    if zero_functions:
        note = f"{note}; no stored functions for binary {binary_id}, byte coverage is undefined"
    return {
        "binary_id": binary_id,
        "image_base": image_base,
        "function_count": len(function_extents),
        "sections": entries,
        "totals": {
            "size": total_bytes,
            "covered": total_covered,
            "uncovered": total_bytes - total_covered,
            "coverage_pct": None if zero_functions else _percent(total_covered, total_bytes),
        },
        "note": note,
    }

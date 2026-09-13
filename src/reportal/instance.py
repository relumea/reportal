"""What this reportal instance can do, for a client that has to ask.

The hosted portal answers ``GET /v2/config``; locally the same question is
"which features are on, what are the limits in force, and which versions are
behind them".  A client that wants to know whether the AI extras, remote
ingestion or the similarity extra are available would otherwise have to probe
and guess, and every cap that bounds a request lives in a different module.

``describe`` is a pure read: it imports nothing heavy, runs no engine call,
makes no network call and writes nothing.  ``available()``-style probes are
import checks, so the payload is cheap enough for a client to fetch on start.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal import (
    __version__,
    analysis_log,
    archive,
    bulk_actions,
    comments,
    conversations,
    graph,
    journal,
    knowledge,
    llm,
    remote_ingest,
    similarity,
)
from reportal._paths import db_path


def _engine_status() -> dict[str, Any]:
    """The engine's availability and where it was imported from."""
    from reportal import engines

    engine = engines.get_engine()
    return {
        "available": engine.available(),
        "origin": engine.origin,
        "backends": list(engines.DECOMPILER_BACKENDS),
        "severities": list(engines.SECURITY_SEVERITIES),
    }


def _llm_status() -> dict[str, Any]:
    """Whether the AI bridge is configured, and the model it would send."""
    client = llm.get_client()
    return {
        "configured": client.available(),
        "model": client.model,
        "kinds": sorted(llm.AI_KINDS),
    }


def _database_status() -> dict[str, Any]:
    """The workspace database path and whether it exists yet."""
    path = db_path()
    return {"path": str(path), "exists": path.is_file()}


def _table_count() -> int:
    """How many tables the schema currently holds, or 0 without a database."""
    path = db_path()
    if not path.is_file():
        return 0
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()
    return int(row[0]) if row else 0


def _tool_counts() -> dict[str, int]:
    """The MCP tool registry's totals, by annotation."""
    from reportal import integrations

    return integrations.tool_totals()


def limits() -> dict[str, int]:
    """Every cap that bounds a request, a scan or a stored payload.

    ``api`` is imported here rather than at module level: it imports every
    writer module and serves the route that reads this payload, so a top-level
    import would close a cycle.
    """
    from reportal import api, store

    return {
        "max_upload_bytes": api.MAX_UPLOAD_BYTES,
        "max_upload_files": api.MAX_UPLOAD_FILES,
        "max_zip_password_chars": api.ZIP_PASSWORD_MAX_CHARS,
        "max_function_size": api.MAX_FUNCTION_SIZE,
        "max_analysis_limit": store.MAX_ANALYSIS_LIMIT,
        "max_search_limit": store.MAX_SEARCH_LIMIT,
        "max_bulk_ids": bulk_actions.MAX_BULK_IDS,
        "max_comment_chars": comments.MAX_COMMENT_CHARS,
        "max_log_limit": analysis_log.MAX_LOG_LIMIT,
        "max_log_message_chars": analysis_log.MAX_MESSAGE_CHARS,
        "max_journal_list_limit": journal.MAX_LIST_LIMIT,
        "max_journal_file_bytes": journal.MAX_FILE_BYTES,
        "max_context_chars": conversations.MAX_CONTEXT_CHARS,
        "max_document_bytes": knowledge.MAX_DOCUMENT_BYTES,
        "max_chunks_per_document": knowledge.MAX_CHUNKS_PER_DOCUMENT,
        "max_graph_nodes": graph.MAX_GRAPH_NODES,
        "max_graph_edges": graph.MAX_GRAPH_EDGES,
        "max_archive_member_bytes": archive.MAX_MEMBER_BYTES,
        "max_archive_total_bytes": archive.MAX_TOTAL_BYTES,
        "max_archive_members": archive.MAX_MEMBERS,
        "max_archive_compression_ratio": archive.MAX_COMPRESSION_RATIO,
        "max_remote_redirects": remote_ingest.MAX_REDIRECTS,
        "max_remote_bytes": remote_ingest.MAX_BYTES,
        "remote_timeout_seconds": int(remote_ingest.FETCH_TIMEOUT_SECONDS),
    }


def features() -> dict[str, Any]:
    """Which optional paths are on, and what turns each one on.

    Nothing here reaches the network: a feature reports configured state, and
    the two guarded paths (the AI bridge and URL ingestion) stay off until the
    workspace opts in.
    """
    from reportal import graph_backends

    return {
        "llm": _llm_status()["configured"],
        "remote_ingest": remote_ingest.remote_enabled(),
        "similarity": similarity.available(),
        "graph_backend": graph_backends.configured_backend_name(),
        "graph_backends": [backend.name for backend in graph_backends.graph_backends()],
        "auth": "single-user",
        "sandbox": False,
        "external_sources": False,
    }


def describe() -> dict[str, Any]:
    """The whole instance description: versions, features, limits and counts."""
    limits_in_force = limits()
    return {
        "name": "reportal",
        "version": __version__,
        "engine": _engine_status(),
        "llm": _llm_status(),
        "database": {**_database_status(), "tables": _table_count()},
        "features": features(),
        "limits": limits_in_force,
        "mcp": _tool_counts(),
    }

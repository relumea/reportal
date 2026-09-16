"""Deterministic knowledge graph over rows reportal already stores.

The graph is derived, never authored: a rebuild reads the binary row, its
functions, the recorded matches, the binary-scoped knowledge documents, the
stored struct, capability, unstrip and triage scans and the binary's tags,
and writes one node and one edge row per fact.  No LLM, no external store and
no engine run is involved, so the same rows always produce the same graph and
a rebuild is idempotent.

Node kinds: ``binary``, ``function``, ``document``, ``struct``, ``tag``,
``capability`` and ``library``.  Relations: ``contains``, ``documented-by``,
``has-capability``, ``has-tag``, ``recovered`` and ``identifies`` all start at
the binary; ``matched-with`` links two of its functions; ``mentions`` links a
document to a function or struct its text names.

Call edges (``function -calls-> function``) are deliberately not built.
Nothing in the store carries them: the call graph lives in the rebrew project
and is read per function through ``rebrew xrefs``, so deriving them here would
turn one rebuild into thousands of engine calls.  The relation is omitted
rather than approximated.

A node id is ``b<binary_id>:<kind>:<key>``, so it is unique across binaries
and the node route needs no binary context.  An edge id is
``<source>|<rel>|<target>``, which makes both tables reproducible row for row.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from typing import Any

from reportal import knowledge, store

# Node kinds, in the order a rebuild adds them.
NODE_BINARY = "binary"
NODE_FUNCTION = "function"
NODE_DOCUMENT = "document"
NODE_STRUCT = "struct"
NODE_TAG = "tag"
NODE_CAPABILITY = "capability"
NODE_LIBRARY = "library"

GRAPH_NODE_KINDS: tuple[str, ...] = (
    NODE_BINARY,
    NODE_FUNCTION,
    NODE_DOCUMENT,
    NODE_STRUCT,
    NODE_TAG,
    NODE_CAPABILITY,
    NODE_LIBRARY,
)

# Edge relations.
REL_CONTAINS = "contains"
REL_DOCUMENTED_BY = "documented-by"
REL_HAS_CAPABILITY = "has-capability"
REL_HAS_TAG = "has-tag"
REL_RECOVERED = "recovered"
REL_IDENTIFIES = "identifies"
REL_MATCHED_WITH = "matched-with"
REL_MENTIONS = "mentions"

# Caps on one binary's graph.  A corpus binary can carry thousands of
# functions, so a rebuild stops rather than writing an unbounded table; the
# node cap is spent in :data:`GRAPH_NODE_KINDS` order, the edge cap in the
# relation order below, and the build reports `truncated` when either is hit.
MAX_GRAPH_NODES = 20000
MAX_GRAPH_EDGES = 50000

# Weight of an edge that carries no measure of its own.  A matched-with edge
# instead carries the recorded similarity.
DEFAULT_EDGE_WEIGHT = 1.0

# Shortest entity name a document may mention.  A shorter name is dropped:
# two or three characters would match inside ordinary prose words.
MENTION_MIN_NAME_LENGTH = 4

# A VA literal in document text: a word-bounded `0x` hex run, so `a0x1234`
# and `0x1234z` are not literals.
_VA_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")

# Characters that may appear in an identifier; a mention never matches inside
# a longer identifier.
_IDENTIFIER_CHARS = r"[0-9A-Za-z_]"


def _name_pattern(names: Iterable[str]) -> re.Pattern[str] | None:
    """Compile one alternation matching any accepted *name* at a word boundary."""
    qualified = sorted(
        {name.strip() for name in names if len(name.strip()) >= MENTION_MIN_NAME_LENGTH}
    )
    if not qualified:
        return None
    body = "|".join(re.escape(name) for name in qualified)
    return re.compile(rf"(?<!{_IDENTIFIER_CHARS})(?:{body})(?!{_IDENTIFIER_CHARS})")


def _canonical_va(token: str) -> str:
    """Return a VA literal in canonical lower-case form, without leading zeros."""
    return f"0x{int(token, 16):x}"


def entity_mentions(text: str, *, names: Iterable[str]) -> set[str]:
    """Return the entity names and VA literals *text* mentions.

    A name matches only at an identifier boundary and only when it reaches
    :data:`MENTION_MIN_NAME_LENGTH`, so a short name never matches as a
    substring of a longer word.  A VA literal is any word-bounded ``0x`` hex
    token, returned lower-cased and stripped of leading zeros, so the same
    address written ``0x00401000`` and ``0x401000`` yields one token.
    """
    found: set[str] = set()
    pattern = _name_pattern(names)
    if pattern is not None:
        found.update(pattern.findall(text))
    found.update(_canonical_va(match.group()) for match in _VA_RE.finditer(text))
    return found


def _as_int(value: Any) -> int | None:
    """Return an engine-supplied address as an int, or None when it is not one."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


def _entries(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the dict entries under *payload[key]*, ignoring any other shape."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _scan(conn: sqlite3.Connection, binary_id: int, kind: str) -> dict[str, Any]:
    """Return a binary's stored scan of *kind*, or an empty object."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return {}
    stored = store.get_scan(conn, analysis_id, kind)
    return stored if stored is not None else {}


def _function_label(function: dict[str, Any]) -> str:
    """Return a function's display label: its name, else its placeholder VA name."""
    name = str(function["name"] or "").strip()
    return name or f"sub_{int(function['va']):x}"


def _library_entries(
    conn: sqlite3.Connection, binary_id: int
) -> list[tuple[str, str, dict[str, Any]]]:
    """Return ``(key, label, meta)`` per identified library, sorted by key.

    A key is the module the candidate belongs to when the engine reported one,
    else its kind, else its name.  The unstrip proposals, the triage dossier's
    library section and its FLIRT matches are merged under that key; the first
    source to name a key sets its kind and the highest confidence wins.
    """
    found: dict[str, dict[str, Any]] = {}

    def remember(key: str, kind: str, source: str, confidence: float) -> None:
        if not key:
            return
        existing = found.get(key)
        if existing is None:
            found[key] = {"kind": kind, "source": source, "confidence": confidence}
            return
        existing["confidence"] = max(float(existing["confidence"]), confidence)

    unstrip = _scan(conn, binary_id, store.SCAN_KIND_UNSTRIP)
    for proposal in _entries(unstrip, "proposals"):
        module = str(proposal.get("module") or "").strip()
        kind = str(proposal.get("kind") or "").strip()
        remember(
            module or kind,
            kind,
            "unstrip",
            float(proposal.get("confidence") or 0.0),
        )

    triage = _scan(conn, binary_id, store.SCAN_KIND_TRIAGE)
    for entry in _entries(triage, "library"):
        module = str(entry.get("module") or "").strip()
        kind = str(entry.get("kind") or "").strip()
        remember(
            module or str(entry.get("name") or "").strip(),
            kind,
            "triage",
            float(entry.get("confidence") or 0.0),
        )
    flirt = triage.get("flirt")
    if isinstance(flirt, dict):
        for match in _entries(flirt, "matches"):
            remember(str(match.get("name") or "").strip(), "flirt", "flirt", 0.0)

    return [(key, key, found[key]) for key in sorted(found)]


def build_graph(conn: sqlite3.Connection, *, binary_id: int) -> dict[str, Any]:
    """Rebuild one binary's graph from the stored rows; returns its counts.

    The previous graph is replaced only after the new one is assembled, so an
    interrupted rebuild leaves the stored graph as it was.  Raises
    :class:`KeyError` for an unknown binary.

    Returns ``{"binary_id", "nodes", "edges", "truncated", "built_at"}``.
    ``truncated`` is true when :data:`MAX_GRAPH_NODES` or
    :data:`MAX_GRAPH_EDGES` stopped the build early.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    state = {"truncated": False}

    def node_id(kind: str, key: str) -> str:
        return f"b{binary_id}:{kind}:{key}"

    def add_node(kind: str, key: str, label: str, meta: dict[str, Any]) -> str | None:
        identifier = node_id(kind, key)
        if identifier in nodes:
            return identifier
        if len(nodes) >= MAX_GRAPH_NODES:
            state["truncated"] = True
            return None
        nodes[identifier] = {
            "id": identifier,
            "kind": kind,
            "key": key,
            "label": label,
            "meta": meta,
        }
        return identifier

    def add_edge(
        source: str | None,
        rel: str,
        target: str | None,
        *,
        weight: float = DEFAULT_EDGE_WEIGHT,
        meta: dict[str, Any] | None = None,
    ) -> None:
        if source is None or target is None or source not in nodes or target not in nodes:
            return
        identifier = f"{source}|{rel}|{target}"
        if identifier in edges:
            return
        if len(edges) >= MAX_GRAPH_EDGES:
            state["truncated"] = True
            return
        edges[identifier] = {
            "id": identifier,
            "source": source,
            "target": target,
            "rel": rel,
            "weight": weight,
            "meta": meta or {},
        }

    binary_node = add_node(
        NODE_BINARY,
        str(binary_id),
        str(binary["name"]),
        {
            "format": str(binary["format"]),
            "arch": str(binary["arch"]),
            "size": int(binary["size"]),
            "sha256": str(binary["sha256"] or ""),
        },
    )

    functions = sorted(
        store.list_functions(conn, binary_id=binary_id), key=lambda row: int(row["va"])
    )
    matches_by_function = store.list_matches_for_functions(
        conn, [int(function["id"]) for function in functions]
    )
    function_names: dict[str, list[str]] = {}
    function_by_va: dict[int, list[str]] = {}
    for function in functions:
        identifier = add_node(
            NODE_FUNCTION,
            str(function["id"]),
            _function_label(function),
            {
                "va": int(function["va"]),
                "size": int(function["size"]),
                "status": str(function["status"]),
                "name_source": str(function["name_source"]),
            },
        )
        if identifier is None:
            continue
        add_edge(binary_node, REL_CONTAINS, identifier)
        name = str(function["name"] or "").strip()
        if name:
            function_names.setdefault(name, []).append(identifier)
        function_by_va.setdefault(int(function["va"]), []).append(identifier)

    documents: list[tuple[str, str]] = []
    for document in store.list_documents(
        conn, scope_kind=knowledge.SCOPE_KIND_BINARY, scope_id=binary_id
    ):
        stored = store.get_document(conn, int(document["id"]))
        identifier = add_node(
            NODE_DOCUMENT,
            str(document["id"]),
            str(document["title"]),
            {
                "source": str(document["source"]),
                "mime": str(document["mime"]),
                "size": int(document["size"]),
                "chunk_count": int(document["chunk_count"]),
            },
        )
        if identifier is None:
            continue
        add_edge(binary_node, REL_DOCUMENTED_BY, identifier)
        documents.append((identifier, str(stored["text"]) if stored else ""))

    struct_names: dict[str, list[str]] = {}
    struct_by_va: dict[int, list[str]] = {}
    struct_scan = _scan(conn, binary_id, store.SCAN_KIND_STRUCTS)
    struct_entries = sorted(
        _entries(struct_scan, "structs"), key=lambda entry: str(entry.get("name") or "")
    )
    for entry in struct_entries:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        identifier = add_node(
            NODE_STRUCT,
            name,
            name,
            {
                "va": _as_int(entry.get("va")),
                "evidence": _as_int(entry.get("evidence")),
                "functions": _as_int(entry.get("functions")),
                "semantic": bool(entry.get("semantic")),
            },
        )
        if identifier is None:
            continue
        add_edge(binary_node, REL_RECOVERED, identifier)
        struct_names.setdefault(name, []).append(identifier)
        va = _as_int(entry.get("va"))
        if va is not None:
            struct_by_va.setdefault(va, []).append(identifier)

    for tag in store.get_binary_tags(conn, binary_id):
        identifier = add_node(NODE_TAG, str(tag["id"]), str(tag["name"]), {})
        add_edge(binary_node, REL_HAS_TAG, identifier)

    capability_scan = _scan(conn, binary_id, store.SCAN_KIND_CAPABILITIES)
    capability_entries = sorted(
        _entries(capability_scan, "capabilities"),
        key=lambda entry: str(entry.get("name") or ""),
    )
    for entry in capability_entries:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        identifier = add_node(
            NODE_CAPABILITY,
            name,
            name,
            {
                "confidence": str(entry.get("confidence") or ""),
                "evidence_count": _as_int(entry.get("evidence_count")) or 0,
                "description": str(entry.get("description") or ""),
            },
        )
        add_edge(binary_node, REL_HAS_CAPABILITY, identifier)

    for key, label, meta in _library_entries(conn, binary_id):
        identifier = add_node(NODE_LIBRARY, key, label, meta)
        add_edge(binary_node, REL_IDENTIFIES, identifier)

    mention_names = set(function_names) | set(struct_names)
    for document_id, text in documents:
        for token in sorted(entity_mentions(text, names=mention_names)):
            for target in function_names.get(token, []):
                add_edge(document_id, REL_MENTIONS, target, meta={"token": token})
            for target in struct_names.get(token, []):
                add_edge(document_id, REL_MENTIONS, target, meta={"token": token})
            if token in function_names or token in struct_names:
                continue
            va = _as_int(token)
            if va is None:
                continue
            for target in function_by_va.get(va, []):
                add_edge(document_id, REL_MENTIONS, target, meta={"token": token})
            for target in struct_by_va.get(va, []):
                add_edge(document_id, REL_MENTIONS, target, meta={"token": token})

    for function in functions:
        source = node_id(NODE_FUNCTION, str(function["id"]))
        if source not in nodes:
            continue
        for match in matches_by_function.get(int(function["id"]), ()):
            target = node_id(NODE_FUNCTION, str(match["candidate_function_id"]))
            if target not in nodes:
                continue
            add_edge(
                source,
                REL_MATCHED_WITH,
                target,
                weight=float(match["similarity"]),
                meta={"confidence": float(match["confidence"])},
            )

    if binary_node is not None:
        nodes[binary_node]["meta"]["truncated"] = state["truncated"]

    store.delete_graph(conn, binary_id)
    for identifier in sorted(nodes):
        node = nodes[identifier]
        store.add_graph_node(
            conn,
            node_id=node["id"],
            binary_id=binary_id,
            kind=node["kind"],
            key=node["key"],
            label=node["label"],
            meta=node["meta"],
        )
    for identifier in sorted(edges):
        edge = edges[identifier]
        store.add_graph_edge(
            conn,
            edge_id=edge["id"],
            binary_id=binary_id,
            source=edge["source"],
            target=edge["target"],
            rel=edge["rel"],
            weight=edge["weight"],
            meta=edge["meta"],
        )
    return {
        "binary_id": binary_id,
        "nodes": len(nodes),
        "edges": len(edges),
        "truncated": state["truncated"],
        "built_at": store.now(),
    }


def graph_payload(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    kind: str | None = None,
    include_documents: bool = False,
) -> dict[str, Any]:
    """Return one binary's stored graph for a view, with degrees computed.

    Document nodes are left out unless *include_documents* is true, since a
    document per ingested note and its mention edges dwarf the rest of a graph;
    without them every ``mentions`` edge disappears with its endpoint.  *kind*
    keeps a single node kind, and the edges are then the ones with both
    endpoints kept, so a degree is the count of a node's edges in the returned
    set, not in the stored graph.

    The payload is ``{"nodes", "edges", "counts", "truncated"}``; a node is
    ``{"id", "kind", "key", "label", "degree", "meta"}``.
    """
    stored_nodes = store.list_graph_nodes(conn, binary_id)
    stored_edges = store.list_graph_edges(conn, binary_id)
    selected = [
        node
        for node in stored_nodes
        if (include_documents or node["kind"] != NODE_DOCUMENT)
        and (kind is None or node["kind"] == kind)
    ]
    allowed = {node["id"] for node in selected}
    payload_edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "rel": edge["rel"],
            "weight": edge["weight"],
        }
        for edge in stored_edges
        if edge["source"] in allowed and edge["target"] in allowed
    ]
    degrees: dict[str, int] = {}
    for edge in payload_edges:
        degrees[edge["source"]] = degrees.get(edge["source"], 0) + 1
        degrees[edge["target"]] = degrees.get(edge["target"], 0) + 1
    counts = dict.fromkeys(GRAPH_NODE_KINDS, 0)
    payload_nodes: list[dict[str, Any]] = []
    for node in selected:
        counts[node["kind"]] = counts.get(node["kind"], 0) + 1
        payload_nodes.append(
            {
                "id": node["id"],
                "kind": node["kind"],
                "key": node["key"],
                "label": node["label"],
                "degree": degrees.get(node["id"], 0),
                "meta": node["meta"],
            }
        )
    binary_node = next((node for node in stored_nodes if node["kind"] == NODE_BINARY), None)
    truncated = bool(binary_node["meta"].get("truncated")) if binary_node else False
    return {
        "nodes": payload_nodes,
        "edges": payload_edges,
        "counts": counts,
        "truncated": truncated,
    }


def _endpoint(node: dict[str, Any], weight: float) -> dict[str, Any]:
    """One neighbor entry: the other endpoint's identity and the edge weight."""
    return {
        "id": node["id"],
        "kind": node["kind"],
        "key": node["key"],
        "label": node["label"],
        "weight": weight,
    }


def _grouped(groups: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Sort one incoming or outgoing map by relation, each list by neighbor."""
    return {
        rel: sorted(entries, key=lambda entry: (entry["label"], entry["id"]))
        for rel, entries in sorted(groups.items())
    }


def neighbors(conn: sqlite3.Connection, *, node_id: str) -> dict[str, Any]:
    """Return one node with its edges grouped by relation.

    The result is ``{"node", "incoming", "outgoing"}``; the incoming and
    outgoing maps are keyed by relation, each holding the other endpoint's id,
    kind, label and the edge weight.  Raises :class:`KeyError` for an unknown
    node id.
    """
    node = store.get_graph_node(conn, node_id)
    if node is None:
        raise KeyError(f"no graph node {node_id}")
    edges = store.list_graph_edges_for_node(conn, node_id)
    incoming: dict[str, list[dict[str, Any]]] = {}
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if edge["source"] == node_id:
            other = store.get_graph_node(conn, edge["target"])
            if other is not None:
                outgoing.setdefault(edge["rel"], []).append(_endpoint(other, edge["weight"]))
        if edge["target"] == node_id:
            other = store.get_graph_node(conn, edge["source"])
            if other is not None:
                incoming.setdefault(edge["rel"], []).append(_endpoint(other, edge["weight"]))
    return {
        "node": {
            "id": node["id"],
            "kind": node["kind"],
            "key": node["key"],
            "label": node["label"],
            "degree": len(edges),
            "meta": node["meta"],
        },
        "incoming": _grouped(incoming),
        "outgoing": _grouped(outgoing),
    }

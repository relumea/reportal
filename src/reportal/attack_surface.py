"""The attack surface of one stored binary, derived from its stored scans.

Zenyard's agent "maps out relevant attack surfaces in minutes".  reportal
already stores every signal such a map needs: the ``protocols`` inference,
the three ``behavior`` domains, the ``capabilities`` classification, the
``threat`` report's network IOCs and the ``crypto`` scan.  This module
composes them at read time the way :mod:`reportal.details` does, so it runs
no engine, touches no network and writes nothing.

Three groups, each one row per matched item with the evidence that named
it and the scan it came from:

- ``network``: the stored protocol inferences, the ``networking``
  capability and the threat scan's URL/domain/IPv4 IOCs;
- ``local_input``: the filesystem and execution behavior findings beside
  the file-io, registry and process-execution capabilities;
- ``crypto``: the crypto capability and the stored crypto scan's findings.

Each read reports the ``sources`` it used.  A binary whose scans are all
missing is not an error at the composition level: ``available`` is false
with the commands that fill the gaps, and the route answers 404 `no-scan`.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal import details, store

# The scans the map composes, in the order they are reported.
SOURCES = ("protocols", "behavior", "capabilities", "threat", "crypto")

# The command that produces each scan, for the hint a missing source carries.
SOURCE_COMMANDS = {
    "protocols": "reportal protocols",
    "behavior": "reportal behavior",
    "capabilities": "reportal capabilities",
    "threat": "reportal threat",
    "crypto": "reportal crypto-scan",
}

# Behavior domains the local-input group reads; networking lives in the
# network group through the protocols scan instead.
LOCAL_DOMAINS = ("filesystem", "execution")

# Capabilities each group reads.  Networking and crypto are exact groups of
# their own; the local group is the input surface (files, the registry and
# launched processes).
NETWORK_CAPABILITIES = frozenset({"networking"})
LOCAL_CAPABILITIES = frozenset({"file-io", "registry", "process-execution"})
CRYPTO_CAPABILITIES = frozenset({"crypto"})

# Threat IOC categories that name a remote endpoint.
NETWORK_IOCS = ("urls", "domains", "ipv4")

# Rows a group carries.  The summary counts stay exact when capped.
MAX_ROWS = 100


def _scan(conn: sqlite3.Connection, binary_id: int, kind: str) -> dict[str, Any]:
    """The binary's stored scan of *kind*, or an empty mapping."""
    found = details.stored_scan(conn, binary_id, kind)
    return found if isinstance(found, dict) else {}


def _behavior_scans(conn: sqlite3.Connection, binary_id: int) -> dict[str, dict[str, Any]]:
    """The stored behavior scans by domain, missing domains left out."""
    from reportal import behavior

    found: dict[str, dict[str, Any]] = {}
    for domain, kind in behavior.DOMAIN_SCAN_KINDS.items():
        scan = _scan(conn, binary_id, kind)
        if scan:
            found[domain] = scan
    return found


def _capability_rows(scan: dict[str, Any], names: frozenset[str]) -> list[dict[str, Any]]:
    """The stored capability entries whose name is in *names*."""
    rows: list[dict[str, Any]] = []
    capabilities = scan.get("capabilities")
    if not isinstance(capabilities, list):
        return rows
    for entry in capabilities:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("name") or "") in names:
            rows.append(
                {
                    "name": str(entry.get("name")),
                    "description": str(entry.get("description") or ""),
                    "confidence": str(entry.get("confidence") or ""),
                    "evidence_count": int(entry.get("evidence_count") or 0),
                    "source": "capabilities",
                }
            )
    return rows


def _protocol_rows(scan: dict[str, Any]) -> list[dict[str, Any]]:
    """The stored protocol inferences as surface rows."""
    rows: list[dict[str, Any]] = []
    protocols = scan.get("protocols")
    if not isinstance(protocols, list):
        return rows
    for entry in protocols:
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "name": str(entry.get("protocol")),
                "description": str(entry.get("description") or ""),
                "confidence": str(entry.get("confidence") or ""),
                "evidence_count": len(entry.get("evidence") or []),
                "source": "protocols",
            }
        )
    return rows


def _finding_rows(scan: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """A stored behavior or crypto scan's findings as surface rows."""
    rows: list[dict[str, Any]] = []
    findings = scan.get("findings")
    if not isinstance(findings, list):
        return rows
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "name": str(entry.get("name")),
                "description": str(entry.get("detail") or ""),
                "confidence": str(entry.get("confidence") or ""),
                "evidence_count": int(entry.get("count") or 1),
                "source": source,
            }
        )
    return rows


def _ioc_rows(scan: dict[str, Any]) -> list[dict[str, Any]]:
    """The threat scan's network IOCs as surface rows."""
    rows: list[dict[str, Any]] = []
    iocs = scan.get("iocs")
    if not isinstance(iocs, dict):
        return rows
    for category in NETWORK_IOCS:
        entries = iocs.get(category)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            value = str(entry.get("value") or "")
            if value:
                rows.append(
                    {
                        "name": value,
                        "description": f"threat indicator ({category})",
                        "confidence": "",
                        "evidence_count": 1,
                        "source": "threat",
                    }
                )
    return rows


def _group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """One surface group: the rows capped, the count exact."""
    ordered = sorted(rows, key=lambda row: (row["name"], row["source"]))
    capped = ordered[:MAX_ROWS]
    return {"rows": capped, "count": len(ordered)}


def attack_surface(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Compose one binary's attack surface from its stored scans.

    Raises :class:`KeyError` for an unknown binary.  ``available`` is false
    when no source scan is stored, with ``sources`` naming each input,
    whether it is stored and the command that fills it in.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    capabilities = _scan(conn, binary_id, store.SCAN_KIND_CAPABILITIES)
    protocols = _scan(conn, binary_id, store.SCAN_KIND_PROTOCOLS)
    threat = _scan(conn, binary_id, store.SCAN_KIND_THREAT)
    crypto = _scan(conn, binary_id, store.SCAN_KIND_CRYPTO)
    behaviors = _behavior_scans(conn, binary_id)

    network = _protocol_rows(protocols)
    network.extend(_capability_rows(capabilities, NETWORK_CAPABILITIES))
    network.extend(_ioc_rows(threat))
    local_input: list[dict[str, Any]] = []
    for domain in LOCAL_DOMAINS:
        scan = behaviors.get(domain)
        if scan:
            local_input.extend(_finding_rows(scan, f"behavior/{domain}"))
    local_input.extend(_capability_rows(capabilities, LOCAL_CAPABILITIES))
    crypto_rows = _capability_rows(capabilities, CRYPTO_CAPABILITIES)
    if crypto:
        crypto_rows.extend(_finding_rows(crypto, "crypto"))

    sources = []
    for name, present in (
        ("protocols", bool(protocols)),
        ("behavior", bool(behaviors)),
        ("capabilities", bool(capabilities)),
        ("threat", bool(threat)),
        ("crypto", bool(crypto)),
    ):
        sources.append(
            {
                "scan": name,
                "stored": present,
                "command": SOURCE_COMMANDS[name],
            }
        )
    available = any(entry["stored"] for entry in sources)
    return {
        "binary_id": binary_id,
        "binary_name": str(binary["name"]),
        "available": available,
        "network": _group(network),
        "local_input": _group(local_input),
        "crypto": _group(crypto_rows),
        "sources": sources,
    }

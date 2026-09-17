"""Deterministic protocol inference over a binary's imports and strings.

The hosted RevEng.AI portal recovers the network protocols a binary speaks
with a model.  reportal reproduces the deterministic half locally: the
import table and the extracted strings (``rebrew imports`` / ``rebrew
strings``, both standalone) are matched against the fixed table in
:data:`PROTOCOLS`, so a scan needs no LLM and makes no network call.

This goes further than the ``networking`` behavior domain, which only states
that socket or HTTP API families are used.  Here a concrete protocol family
is named with the evidence that named it:

* an **import** match against a dedicated API family (``WinHttpSendRequest``,
  ``ldap_bind``, ``FtpGetFile``) is ``high`` confidence; the generic socket
  family on ``tcp``/``udp`` is ``medium``;
* a **scheme** in a ``scheme://`` literal (``ftp://``, ``ws://``,
  ``ldap://``) is ``high``, since the scheme is the protocol;
* a protocol **literal** (``HTTP/1.1``, ``EHLO``, ``USER ``) is ``medium``.

A protocol with both an import match and a scheme or literal match is raised
to ``high``: a named rule (:func:`_confidence`), since two independent
signals agree.

Port evidence is optional and conservative.  A port is recognized only as
the decimal number after a colon in a string that also carries a host or a
URL (a ``scheme://`` form or a dotted-decimal IPv4 literal), and only when
that number is one of the well-known ports in :data:`WELL_KNOWN_PORTS`.
A lone ``80`` or ``443`` constant therefore yields nothing, while
``1.2.3.4:22`` yields ``ssh``.  The port number is reported as a ``string``
piece of evidence, so the evidence kinds stay ``import``/``scheme``/
``string``.

Inference is not proof of use: an import means the binary can call that API
and a literal means the text is present, not that a session was opened.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from reportal import capabilities, engines, store
from reportal.capabilities import CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, ImportRule
from reportal.engines import RebrewEngine

# Evidence kinds.  A port match is reported as `string` evidence (see the
# module docstring), so these three are the whole set.
KIND_IMPORT = "import"
KIND_SCHEME = "scheme"
KIND_STRING = "string"

# Sort rank per evidence kind; imports lead, then schemes, then literals.
_EVIDENCE_RANK = {KIND_IMPORT: 0, KIND_SCHEME: 1, KIND_STRING: 2}

# Strings inspected by one scan.  The engine can return tens of thousands and
# every rule regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Note a payload carries when nothing matched; an empty result is valid.
NO_EVIDENCE_NOTE = "no protocol evidence in the imports or strings"

# Well-known decimal port literals, and the protocols that own them.  This is
# the single source for both the per-protocol default ports a payload reports
# and the optional host:port evidence.  A port with several owners (443) names
# every one of them.
WELL_KNOWN_PORTS: dict[int, tuple[str, ...]] = {
    21: ("ftp",),
    22: ("ssh",),
    23: ("telnet",),
    25: ("smtp",),
    53: ("dns",),
    80: ("http",),
    110: ("pop3",),
    123: ("ntp",),
    143: ("imap",),
    161: ("snmp",),
    389: ("ldap",),
    443: ("https", "quic", "tls"),
    445: ("smb",),
    636: ("ldap",),
    993: ("imap",),
    995: ("pop3",),
    1883: ("mqtt",),
    3389: ("rdp",),
    6667: ("irc",),
    8883: ("mqtt",),
}

# A `scheme://` prefix.  The scheme is the protocol, so a match is `high`
# confidence.
_SCHEME = re.compile(r"\b([A-Za-z][A-Za-z0-9+.\-]*)://")

# A host or URL in a string: a `scheme://` form, a dotted-decimal IPv4
# literal or a dotted host name.  It gates the port rule, so a bare `80` or
# `443` constant in a string with no host is never port evidence.
_HOST_OR_URL = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://"
    r"|(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
    r"|(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}",
    re.IGNORECASE,
)

# The port number in a `host:port` form.
_PORT = re.compile(r"(?<=[:=])\s*(\d{1,5})(?!\d)")


@dataclass(frozen=True)
class ProtocolSpec:
    """One protocol family and the evidence that points at it.

    ``imports`` are :class:`~reportal.capabilities.ImportRule` entries matched
    with the capabilities comparison; ``import_confidence`` is what an import
    hit alone is worth (``medium`` for the generic socket family).
    ``schemes`` are the URL schemes that name the protocol outright.
    ``strings`` are case-sensitive literal patterns.
    """

    protocol: str
    description: str
    imports: tuple[ImportRule, ...] = ()
    import_confidence: str = CONFIDENCE_HIGH
    schemes: tuple[str, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()


def _literal(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)


def _word(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# The WinINet/WinHTTP/libcurl client family.  Both http and https share it:
# an API name says HTTP is spoken, not which scheme on the wire.
_HTTP_CLIENT_IMPORTS = capabilities._prefix(
    "WinHttp",
    "Http",
    "Internet",
    "URLDownloadToFile",
    "curl_easy_",
    "curl_multi_",
)

# The generic Berkeley/Winsock socket family.  It is shared by tcp and udp and
# says only that a socket is used, so an import hit alone is `medium`.
_SOCKET_IMPORTS = capabilities._prefix("WSA") + capabilities._exact(
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "closesocket",
    "shutdown",
    "send",
    "recv",
    "sendto",
    "recvfrom",
    "select",
    "ioctlsocket",
)


# The protocol table.  Rules overlap on purpose (a TLS client is often an
# HTTPS client; an SMB client also uses the socket API), because each entry
# names a protocol family the analyst may care about.
PROTOCOLS: tuple[ProtocolSpec, ...] = (
    ProtocolSpec(
        protocol="http",
        description="Hypertext Transfer Protocol",
        imports=_HTTP_CLIENT_IMPORTS,
        schemes=("http",),
        strings=_literal(r"HTTP/\d(?:\.\d)?", r"\b(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) /"),
    ),
    ProtocolSpec(
        protocol="https",
        description="HTTP over TLS",
        imports=_HTTP_CLIENT_IMPORTS,
        schemes=("https",),
    ),
    ProtocolSpec(
        protocol="tls",
        description="Transport Layer Security",
        imports=capabilities._prefix("SSL_", "TLS_", "OPENSSL"),
        strings=_literal(r"TLSv1(?:\.[0-9])?", r"SSLv[23]"),
    ),
    ProtocolSpec(
        protocol="dns",
        description="Domain Name System",
        imports=capabilities._prefix("DnsQuery", "DnsFree", "DnsRecord", "DnsName")
        + capabilities._exact(
            "gethostbyname",
            "gethostbyaddr",
            "getaddrinfo",
            "getnameinfo",
            "res_query",
            "res_send",
        ),
        strings=_literal(r"\.in-addr\.arpa\b"),
    ),
    ProtocolSpec(
        protocol="ftp",
        description="File Transfer Protocol",
        imports=capabilities._prefix("Ftp"),
        schemes=("ftp",),
        strings=_literal(r"^USER\s", r"^(?:PASS|RETR|STOR|PASV|CWD|LIST|QUIT)\s"),
    ),
    ProtocolSpec(
        protocol="smtp",
        description="Simple Mail Transfer Protocol",
        imports=capabilities._substring("smtp"),
        schemes=("smtp",),
        strings=_literal(r"EHLO\b", r"\bHELO\b", r"MAIL FROM:", r"RCPT TO:", r"^220[ -]"),
    ),
    ProtocolSpec(
        protocol="imap",
        description="Internet Message Access Protocol",
        imports=capabilities._substring("imap"),
        schemes=("imap",),
        strings=_literal(r"^\* OK\b", r"\bCAPABILITY\b", r"\bIMAP4rev1\b"),
    ),
    ProtocolSpec(
        protocol="pop3",
        description="Post Office Protocol 3",
        imports=capabilities._substring("pop3"),
        schemes=("pop3",),
        strings=_literal(r"^\+OK\b", r"^-ERR\b"),
    ),
    ProtocolSpec(
        protocol="irc",
        description="Internet Relay Chat",
        schemes=("irc", "ircs"),
        strings=_literal(r"^NICK\b", r"^JOIN #", r"\bPRIVMSG\b", r"^PING :"),
    ),
    ProtocolSpec(
        protocol="telnet",
        description="Telnet",
        schemes=("telnet",),
        strings=_word(r"\btelnet\b"),
    ),
    ProtocolSpec(
        protocol="ssh",
        description="Secure Shell",
        imports=capabilities._prefix("ssh_", "libssh"),
        schemes=("ssh",),
        strings=_literal(r"SSH-2\.0", r"SSH-1\.99", r"SSH-1\.5"),
    ),
    ProtocolSpec(
        protocol="smb",
        description="Server Message Block",
        imports=capabilities._prefix(
            "NetShare",
            "NetUse",
            "NetConnection",
            "NetSession",
            "NetFile",
            "WNet",
        ),
        strings=_literal(r"\bSMB2?\b"),
    ),
    ProtocolSpec(
        protocol="rdp",
        description="Remote Desktop Protocol",
        imports=capabilities._prefix("WTS"),
        schemes=("rdp",),
        strings=_literal(r"\bRDP\b", r"\bTERMSRV\b"),
    ),
    ProtocolSpec(
        protocol="ldap",
        description="Lightweight Directory Access Protocol",
        imports=capabilities._prefix("ldap"),
        schemes=("ldap", "ldaps"),
        strings=_literal(r"\bobjectClass\b", r"\bdistinguishedName\b", r"\bsAMAccountName\b"),
    ),
    ProtocolSpec(
        protocol="snmp",
        description="Simple Network Management Protocol",
        imports=capabilities._prefix("Snmp", "snmp"),
        strings=_literal(r"\.1\.3\.6\.1\.2\.1\.", r"\.1\.3\.6\.1\.4\.1\.", r"\bSNMPv[123]\b"),
    ),
    ProtocolSpec(
        protocol="ntp",
        description="Network Time Protocol",
        strings=_word(r"\bNTP\b", r"\bNTPv[34]\b"),
    ),
    ProtocolSpec(
        protocol="quic",
        description="QUIC",
        imports=capabilities._prefix("quic_", "ngtcp2", "nghttp3", "msquic"),
        schemes=("quic",),
        strings=_literal(r"\bQUIC\b"),
    ),
    ProtocolSpec(
        protocol="mqtt",
        description="Message Queuing Telemetry Transport",
        imports=capabilities._prefix("mqtt_", "MQTT") + capabilities._substring("mosquitto"),
        schemes=("mqtt", "mqtts"),
        strings=_literal(r"\bMQTT\b", r"\bmosquitto\b"),
    ),
    ProtocolSpec(
        protocol="websocket",
        description="WebSocket",
        imports=capabilities._prefix("WinHttpWebSocket") + capabilities._substring("websocket"),
        schemes=("ws", "wss"),
        strings=_word(r"\bwebsocket\b", r"Sec-WebSocket-Key", r"Upgrade: websocket"),
    ),
    ProtocolSpec(
        protocol="tcp",
        description="Transmission Control Protocol",
        imports=_SOCKET_IMPORTS,
        import_confidence=CONFIDENCE_MEDIUM,
        strings=_word(r"\bTCP\b", r"\bSOCK_STREAM\b"),
    ),
    ProtocolSpec(
        protocol="udp",
        description="User Datagram Protocol",
        imports=_SOCKET_IMPORTS,
        import_confidence=CONFIDENCE_MEDIUM,
        strings=_word(r"\bUDP\b", r"\bSOCK_DGRAM\b"),
    ),
)


def _ports_for(protocol: str) -> list[int]:
    """Return the well-known ports *protocol* owns, ascending."""
    return [port for port, owners in sorted(WELL_KNOWN_PORTS.items()) if protocol in owners]


def _add(
    evidence: dict[str, list[dict[str, str]]],
    seen: dict[str, set[tuple[str, str]]],
    protocol: str,
    kind: str,
    value: str,
) -> None:
    """Record one piece of evidence for *protocol*, collapsing a repeat."""
    marker = (kind, value)
    if marker in seen[protocol]:
        return
    seen[protocol].add(marker)
    evidence[protocol].append({"kind": kind, "value": value})


def _confidence(spec: ProtocolSpec, evidence: Sequence[dict[str, str]]) -> str:
    """Confidence for *spec* given its deduplicated *evidence*.

    A scheme match is the protocol itself, so it is ``high`` on its own.  An
    import match alone is worth the spec's ``import_confidence``.  An import
    plus a scheme or literal match is ``high`` (the named promotion rule),
    since two independent signals agree.  A literal on its own is ``medium``.
    """
    kinds = {item["kind"] for item in evidence}
    named = bool(kinds & {KIND_SCHEME, KIND_STRING})
    if KIND_IMPORT in kinds:
        if named:
            return CONFIDENCE_HIGH
        return spec.import_confidence
    if KIND_SCHEME in kinds:
        return CONFIDENCE_HIGH
    return CONFIDENCE_MEDIUM


def infer_protocols(
    imports: Sequence[dict[str, Any]], strings: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Infer the network protocols *imports* and *strings* point at.

    Returns ``{"protocols", "count", "by_confidence", "notes"}``.  Each entry
    is ``{"protocol", "description", "confidence", "evidence", "ports"}``,
    where evidence is a deduplicated, sorted list of ``{"kind", "value"}``
    pairs (``import``, ``scheme`` or ``string``) and ``ports`` are the
    protocol's well-known ports.  Entries sort by protocol name; ``count`` and
    ``by_confidence`` are exact over the full set.  An empty ``protocols`` is
    a valid result, and its ``notes`` say so.
    """
    evidence: dict[str, list[dict[str, str]]] = {spec.protocol: [] for spec in PROTOCOLS}
    seen: dict[str, set[tuple[str, str]]] = {spec.protocol: set() for spec in PROTOCOLS}

    for entry in imports:
        name = capabilities._import_name(entry)
        if not name:
            continue
        for spec in PROTOCOLS:
            if any(capabilities._import_matches(rule, name) for rule in spec.imports):
                _add(evidence, seen, spec.protocol, KIND_IMPORT, name)

    for entry in strings[:MAX_STRINGS_INSPECTED]:
        text = capabilities._string_text(entry)
        if not text:
            continue
        for match in _SCHEME.finditer(text):
            scheme = match.group(1).casefold()
            for spec in PROTOCOLS:
                if scheme in spec.schemes:
                    _add(evidence, seen, spec.protocol, KIND_SCHEME, scheme)
        for spec in PROTOCOLS:
            for pattern in spec.strings:
                literal = pattern.search(text)
                if literal is not None:
                    _add(evidence, seen, spec.protocol, KIND_STRING, literal.group(0))
        if _HOST_OR_URL.search(text):
            for match in _PORT.finditer(text):
                for protocol in WELL_KNOWN_PORTS.get(int(match.group(1)), ()):
                    _add(evidence, seen, protocol, KIND_STRING, match.group(1))

    results: list[dict[str, Any]] = []
    for spec in sorted(PROTOCOLS, key=lambda item: item.protocol):
        found = evidence[spec.protocol]
        if not found:
            continue
        ordered = sorted(found, key=lambda item: (_EVIDENCE_RANK[item["kind"]], item["value"]))
        results.append(
            {
                "protocol": spec.protocol,
                "description": spec.description,
                "confidence": _confidence(spec, ordered),
                "evidence": ordered,
                "ports": _ports_for(spec.protocol),
            }
        )

    by_confidence = {
        CONFIDENCE_HIGH: sum(1 for entry in results if entry["confidence"] == CONFIDENCE_HIGH),
        CONFIDENCE_MEDIUM: sum(1 for entry in results if entry["confidence"] == CONFIDENCE_MEDIUM),
    }
    notes = [] if results else [NO_EVIDENCE_NOTE]
    return {
        "protocols": results,
        "count": len(results),
        "by_confidence": by_confidence,
        "notes": notes,
    }


def scan_protocols(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RebrewEngine | None = None,
    imports: Sequence[dict[str, Any]] | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Infer a binary's protocols and store the result as the ``protocols`` scan.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies the two standalone engine calls.  *imports*
    and *strings* override the engine payloads outright, which is how tests
    keep the run hermetic.  Strings are capped at :data:`MAX_STRINGS_INSPECTED`.

    Raises :class:`KeyError` for an unknown binary and
    :class:`FileNotFoundError` when its row has no file on disk; an engine
    failure propagates.  Returns ``{"binary_id", "protocols", "count",
    "by_confidence", "notes"}``.
    """
    _binary, path = capabilities.require_binary_file(conn, binary_id)

    source: capabilities.CapabilityIO = engine or engines.get_engine()
    raw_imports, raw_strings = capabilities.load_imports_and_strings(
        path, source, imports=imports, strings=strings
    )
    result = infer_protocols(raw_imports, raw_strings)
    payload = {"binary_id": binary_id, **result}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_PROTOCOLS, payload)
    return payload

"""Local threat report: IOC extraction and a curated ATT&CK mapping.

The hosted RevEng.AI portal pairs a binary with an AI threat report (an analyst
summary, indicators of compromise and MITRE ATT&CK techniques).  reportal
produces the deterministic half locally and leaves the narrative optional:

* :func:`extract_iocs` scans the strings ``rebrew strings`` already returns for
  indicators of compromise, in seven categories (:data:`IOC_CATEGORIES`).
* :func:`map_techniques` maps the binary's import table, its stored capability
  scan and the extracted IOCs onto the fixed ATT&CK table in
  :data:`TECHNIQUES`.
* :func:`build_threat_report` composes them, reads the ``capabilities`` scan the
  store already holds (it never runs that scan), asks the configured LLM for a
  short analyst summary when one is requested and available, and stores the
  whole result as the ``threat`` scan.
* :func:`classify_software` names the binary's software type from the same
  evidence (the stored ``filetype`` and ``capabilities`` scans, the stored
  ``threat`` report's techniques and indicators, and the stored ``triage``
  dossier's string and DLL samples), and :func:`score_threat` aggregates a
  0-100 threat score from it, naming every contribution.

The software type and the score are reportal's own heuristics over the stored
evidence, not the hosted portal's model output, and every payload says so.
They are derived at read time by :func:`classify_binary`, so every surface
shows the same value for the same stored state.

No external threat-intelligence service is contacted and no URL is fetched.
The only network call is the optional LLM narrative, and only when the caller
asks for it and an OpenAI-compatible endpoint is configured.

Rule choices, all on the conservative side:

* A string carrying a printf conversion (``%s``, ``%02x``) is skipped whole,
  because a format template such as ``http://%s/%s`` or ``C:\\\\%s\\\\%s.log``
  would otherwise extract its placeholder scaffolding as an indicator.
* URLs are anchored on a scheme (``http``, ``https``, ``ftp``) and need a
  non-empty host, so ``http://`` alone yields nothing; trailing punctuation is
  trimmed and the host is validated with :func:`urllib.parse.urlsplit`.
* Domains need a dotted label list whose last label is in :data:`COMMON_TLDS`,
  so a dotted version string or a file name does not qualify, and a bare
  hexadecimal blob never does.
* IPv4 octets are validated to ``0..255``; private, loopback and link-local
  addresses are kept and marked in the finding's ``kind`` (``ipv4-private``)
  rather than dropped, since an embedded RFC1918 address is still evidence.
* Emails need a user part and a plausible TLD, like domains.
* Registry paths are anchored on a hive prefix (``HKEY_*`` or its ``HK*``
  abbreviation) and need at least one subkey.
* File paths are anchored on a drive letter (``C:\\``) or an UNC prefix
  (``\\\\server\\share``), never on a bare separator.
* Hashes must be exactly 32, 40 or 64 hexadecimal characters with a non-hex
  boundary on each side, and the ``kind`` names the digest length
  (``md5``/``sha1``/``sha256``).
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from reportal import engines, llm, store

# IOC categories, in the order every payload and view lists them.
IOC_CATEGORY_URLS = "urls"
IOC_CATEGORY_DOMAINS = "domains"
IOC_CATEGORY_IPV4 = "ipv4"
IOC_CATEGORY_IPV6 = "ipv6"
IOC_CATEGORY_EMAILS = "emails"
IOC_CATEGORY_REGISTRY = "registry_paths"
IOC_CATEGORY_FILES = "file_paths"
IOC_CATEGORY_HASHES = "hashes"

IOC_CATEGORIES: tuple[str, ...] = (
    IOC_CATEGORY_URLS,
    IOC_CATEGORY_DOMAINS,
    IOC_CATEGORY_IPV4,
    IOC_CATEGORY_IPV6,
    IOC_CATEGORY_EMAILS,
    IOC_CATEGORY_REGISTRY,
    IOC_CATEGORY_FILES,
    IOC_CATEGORY_HASHES,
)

# Findings kept per category.  A string table can repeat an indicator hundreds
# of times, so the list is bounded; deduplication happens first, which is what
# makes the cap meaningful.
MAX_IOCS_PER_CATEGORY = 25

# Strings inspected by one run.  The engine can return tens of thousands and
# every rule regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = 5000

# Findings kept as evidence per technique; the table is small enough that a
# curated sample reads better than every matching import.
MAX_EVIDENCE_PER_TECHNIQUE = 8

# Confidence ranks a local match carries, strongest first.  An import family
# matched directly is concrete; a capability or IOC match only suggests intent;
# a lone string marker is the weakest signal.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# Kinds the IPv4 rule reports.  A non-public address stays a finding; the kind
# records that it is not routable.
KIND_IPV4 = "ipv4"
KIND_IPV4_PRIVATE = "ipv4-private"

# Kinds the IPv6 rule reports, mirroring the IPv4 pair.
KIND_IPV6 = "ipv6"
KIND_IPV6_PRIVATE = "ipv6-private"

# Cloud instance-metadata endpoints, by finding kind.  A literal hit is
# post-exploitation cloud recon (the LinPEAS-shaped behavior Zenyard's
# malware posts dissect), so the kind names the provider rather than
# merely flagging the address as private.
CLOUD_METADATA_IPS: dict[str, str] = {
    "169.254.169.254": "cloud-aws",
    "169.254.170.2": "cloud-aws-ecs",
    "100.100.100.200": "cloud-alibaba",
    "169.254.0.23": "cloud-tencent",
}
CLOUD_METADATA_HOSTS: dict[str, str] = {
    "metadata.google.internal": "cloud-gcp",
}


def _cloud_kind(value: str) -> str | None:
    """The cloud-metadata kind for an IP or host literal, or None."""
    lowered = value.casefold().rstrip(".")
    if lowered in CLOUD_METADATA_IPS:
        return CLOUD_METADATA_IPS[lowered]
    return CLOUD_METADATA_HOSTS.get(lowered)


# Digest name per hexadecimal length.
HASH_KINDS: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256"}

# The TLDs a domain or email must end in.  A closed set keeps the rule
# conservative: something like ``image.png`` or ``version.4.2`` is not a host.
COMMON_TLDS: frozenset[str] = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "io",
        "co",
        "ai",
        "dev",
        "app",
        "cloud",
        "tech",
        "systems",
        "solutions",
        "security",
        "online",
        "site",
        "website",
        "xyz",
        "top",
        "club",
        "work",
        "link",
        "live",
        "news",
        "blog",
        "shop",
        "store",
        "space",
        "host",
        "fun",
        "me",
        "tv",
        "cc",
        "uk",
        "us",
        "ca",
        "de",
        "fr",
        "nl",
        "ru",
        "cn",
        "jp",
        "in",
        "br",
        "au",
        "pl",
        "it",
        "es",
        "se",
        "no",
        "fi",
        "dk",
        "ch",
        "at",
        "be",
        "cz",
        "gr",
        "pt",
        "ro",
        "hu",
        "ie",
        "il",
        "mx",
        "ar",
        "cl",
        "za",
        "kr",
        "tw",
        "hk",
        "sg",
        "my",
        "th",
        "vn",
        "id",
        "ph",
        "tr",
        "ua",
        "by",
        "kz",
        "su",
        "onion",
    }
)

# A printf conversion.  ``%%`` is a literal percent and deliberately not a
# conversion, so a string carrying only that still gets scanned.
_FORMAT_SPECIFIER = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[hlLqjzt]*[diouxXeEfFgGaAcspn]")

_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\{}|]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", re.IGNORECASE
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w.:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{1,}(?![\w.:])")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}")
_REGISTRY = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS"
    r"|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[^\s\"'<>|]+)+",
    re.IGNORECASE,
)
_DRIVE_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]+")
_UNC_PATH = re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+(?:\\[^\s\"'<>|*?]+)*")
_HASHES: dict[str, re.Pattern[str]] = {
    kind: re.compile(rf"(?<![0-9A-Fa-f])[0-9A-Fa-f]{{{length}}}(?![0-9A-Fa-f])")
    for length, kind in HASH_KINDS.items()
}

# Trailing characters a matched URL, domain or path may have picked up from
# surrounding prose or C syntax.
_TRAILING_PUNCTUATION = ".,;:!?)]}\"'<>"
_HOST = re.compile(r"[A-Za-z0-9._\-:\[\]]+")


class ThreatIO(Protocol):
    """The engine surface a threat report reads; every call is standalone."""

    def available(self) -> bool: ...

    def strings(self, binary: str | Path) -> dict[str, Any]: ...

    def imports(self, binary: str | Path) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique and the local evidence that activates it."""

    attack_id: str
    name: str
    imports: tuple[re.Pattern[str], ...] = ()
    capabilities: tuple[str, ...] = ()
    iocs: tuple[str, ...] = ()


def _patterns(*values: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, re.IGNORECASE) for value in values)


# The curated ATT&CK table.  Import patterns are anchored name matches; a
# capability or IOC category is the weaker, indirect signal that yields medium
# confidence.  Overlap is intentional: process injection also implies thread
# and memory APIs, and a boot-time autostart writes the registry.
TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        attack_id="T1055",
        name="Process Injection",
        imports=_patterns(
            r"^CreateRemoteThread$",
            r"^NtCreateThreadEx$",
            r"^RtlCreateUserThread$",
            r"^QueueUserAPC$",
            r"^SetWindowsHookEx",
            r"^WriteProcessMemory$",
            r"^NtWriteVirtualMemory$",
            r"^VirtualAllocEx$",
            r"^VirtualProtectEx$",
            r"^NtMapViewOfSection$",
            r"^OpenProcess$",
        ),
        capabilities=("memory", "threading"),
    ),
    Technique(
        attack_id="T1059",
        name="Command and Scripting Interpreter",
        imports=_patterns(
            r"^CreateProcess",
            r"^ShellExecute",
            r"^WinExec$",
            r"^system$",
            r"^_system$",
            r"^popen$",
            r"^_popen$",
            r"^_spawn",
            r"^_exec",
            r"^execl",
            r"^execv",
        ),
        capabilities=("process-execution",),
    ),
    Technique(
        attack_id="T1071",
        name="Application Layer Protocol",
        imports=_patterns(
            r"^(?:WSA|WinHttp|WinInet|Internet|Http|Ftp|Icmp|Dns)",
            r"^(?:connect|send|recv|sendto|recvfrom|getaddrinfo|gethostby)$",
            r"^(?:htons|ntohs|inet_addr|inet_ntoa)$",
            r"^URLDownloadToFile$",
        ),
        capabilities=("networking",),
        iocs=(IOC_CATEGORY_URLS, IOC_CATEGORY_DOMAINS, IOC_CATEGORY_IPV4, IOC_CATEGORY_IPV6),
    ),
    Technique(
        attack_id="T1041",
        name="Exfiltration Over C2 Channel",
        imports=_patterns(
            r"^(?:WSA|Internet|WinHttp|Ftp)",
            r"^(?:send|sendto|WSASend|connect|HttpSendRequest)$",
            r"^(?:FtpPutFile|InternetWriteFile)$",
        ),
        capabilities=("networking",),
        iocs=(
            IOC_CATEGORY_URLS,
            IOC_CATEGORY_DOMAINS,
            IOC_CATEGORY_IPV4,
            IOC_CATEGORY_IPV6,
        ),
    ),
    Technique(
        attack_id="T1082",
        name="System Information Discovery",
        imports=_patterns(
            r"^GetSystemInfo$",
            r"^GetNativeSystemInfo$",
            r"^GetComputerName",
            r"^GetUserName",
            r"^GetVersionEx",
            r"^GlobalMemoryStatus",
            r"^GetVolumeInformation",
            r"^GetSystemDirectory",
            r"^GetWindowsDirectory",
            r"^GetSystemMetrics$",
            r"^GetLogicalDrives$",
            r"^EnumSystemFirmwareTables$",
        ),
    ),
    Technique(
        attack_id="T1105",
        name="Ingress Tool Transfer",
        imports=_patterns(
            r"^URLDownloadToFile",
            r"^URLDownloadToCacheFile$",
            r"^InternetReadFile",
            r"^WinHttpReadData$",
            r"^WSARecv",
            r"^recv$",
            r"^FtpGetFile$",
            r"^FtpOpenFile$",
            r"^HttpOpenRequest",
        ),
        capabilities=("networking", "dynamic-loading"),
        iocs=(IOC_CATEGORY_URLS, IOC_CATEGORY_FILES),
    ),
    Technique(
        attack_id="T1112",
        name="Modify Registry",
        imports=_patterns(
            r"^Reg(?:Set|Create|Delete|Save|Restore)",
            r"^NtSetValueKey$",
            r"^SHSetValue$",
            r"^WritePrivateProfileString$",
        ),
        capabilities=("registry",),
        iocs=(IOC_CATEGORY_REGISTRY,),
    ),
    Technique(
        attack_id="T1140",
        name="Deobfuscate/Decode Files or Information",
        imports=_patterns(
            r"^Crypt(?:Decrypt|StringToBinary|BinaryToString|UnprotectMemory)",
            r"^BCryptDecrypt$",
            r"^NCryptDecrypt$",
            r"^(?:inflate|uncompress)$",
            r"^(?:BZ2_|lzma_|ZSTD_)",
            r"^RtlDecompressBuffer$",
        ),
        capabilities=("crypto", "compression"),
    ),
    Technique(
        attack_id="T1485",
        name="Data Destruction",
        imports=_patterns(
            r"^DeleteFile",
            r"^SHFileOperation",
            r"^NtSetInformationFile$",
            r"^MoveFileEx",
        ),
        capabilities=("file-io",),
    ),
    Technique(
        attack_id="T1486",
        name="Data Encrypted for Impact",
        imports=_patterns(
            r"^Crypt(?:Encrypt|GenKey|DeriveKey|GenRandom)",
            r"^BCryptEncrypt$",
            r"^NCryptEncrypt$",
        ),
        capabilities=("crypto",),
    ),
    Technique(
        attack_id="T1547",
        name="Boot or Logon Autostart Execution",
        imports=_patterns(
            r"^Reg(?:Set|Create)",
            r"^CreateService",
            r"^OpenSCManager",
            r"^ChangeServiceConfig",
            r"^StartService",
            r"^WritePrivateProfileString",
            r"^SHSetValue",
        ),
        capabilities=("persistence",),
        iocs=(IOC_CATEGORY_REGISTRY,),
    ),
    Technique(
        attack_id="T1027",
        name="Obfuscated Files or Information",
        imports=_patterns(
            r"^(?:Crypt|BCrypt|NCrypt)",
            r"^(?:inflate|deflate|uncompress|compress)$",
            r"^(?:BZ2_|lzma_|ZSTD_)",
            r"^RtlDecompressBuffer$",
        ),
        capabilities=("crypto", "compression"),
    ),
)


def _entry_text(entry: dict[str, Any]) -> str:
    """Return a string entry's text, or "" when it carries none."""
    return str(entry.get("text") or "")


def _entry_va(entry: dict[str, Any]) -> int | None:
    """Return a string entry's VA as an int, or None when it carries none."""
    value = entry.get("va")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 16)
        except ValueError:
            return None
    return None


def _is_format_string(text: str) -> bool:
    """True when *text* carries a printf conversion, so its rules would misfire.

    ``%%`` is consumed as a literal percent, so a string that only carries one
    is still scanned.
    """
    index = 0
    while True:
        index = text.find("%", index)
        if index < 0:
            return False
        if text.startswith("%%", index):
            index += 2
            continue
        if _FORMAT_SPECIFIER.match(text, index):
            return True
        index += 1


def _is_host(value: str) -> bool:
    """True when *value* looks like a URL host (a dotted name, address or port form)."""
    if not value or not _HOST.fullmatch(value):
        return False
    return any(character.isalnum() for character in value)


def _trim(value: str) -> str:
    """Return *value* without trailing prose or path punctuation."""
    return value.rstrip(_TRAILING_PUNCTUATION + "\\/")


def _plausible_domain(value: str) -> bool:
    """True when *value*'s last label is a known TLD."""
    return value.rsplit(".", 1)[-1].casefold() in COMMON_TLDS


def _private_ipv4(value: str) -> bool:
    """True for RFC1918, loopback and link-local addresses."""
    first, second, *_ = (int(octet) for octet in value.split("."))
    if first in (10, 127):
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return first == 169 and second == 254


def _valid_ipv4(value: str) -> bool:
    """True when every octet fits in a byte."""
    return all(int(octet) <= 255 for octet in value.split("."))


def _strip_ipv4_mapped(text: str) -> str:
    """Blank the IPv4-mapped IPv6 tails so they stay IPv4 findings.

    ``::ffff:8.8.8.8`` parses as an address, but the indicator an analyst
    wants is the dotted quad the IPv4 rule already reports; blanking the
    dotted tail (same length, so offsets hold) keeps one finding, not two.
    """
    return re.sub(r"::ffff:\d{1,3}(?:\.\d{1,3}){3}", lambda m: " " * len(m.group(0)), text)


def _valid_ipv6(value: str) -> str | None:
    """The canonical IPv6 literal in *value*, or None when it is not one.

    ``ipaddress`` is the validator, so compressed and full forms both parse;
    an IPv4-mapped address answers its v4 form and stays in the IPv4
    category, and anything else unparseable is not a finding.  A zone id
    (``fe80::1%eth0``) is an interface name, not an indicator.
    """
    candidate = value.strip("[]").split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return None
    if parsed.ipv4_mapped is not None:
        return None
    return str(parsed)


def _hash_findings(text: str) -> list[tuple[str, str]]:
    """Return ``(value, kind)`` for each hash of an accepted length in *text*."""
    found: list[tuple[str, str]] = []
    for kind, pattern in _HASHES.items():
        found.extend((match.group(0).casefold(), kind) for match in pattern.finditer(text))
    return found


def extract_iocs(strings: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Extract indicators of compromise from engine string entries.

    Returns one list per category in :data:`IOC_CATEGORIES`.  Every finding is
    ``{"value", "kind", "source_va"}``; findings deduplicate by value inside a
    category (first occurrence wins) and each category is capped at
    :data:`MAX_IOCS_PER_CATEGORY`.  A string carrying a printf conversion is
    skipped whole, since a format template would extract placeholder text.
    """
    found: dict[str, list[dict[str, Any]]] = {category: [] for category in IOC_CATEGORIES}
    seen: dict[str, set[str]] = {category: set() for category in IOC_CATEGORIES}

    def add(category: str, value: str, kind: str, va: int | None) -> None:
        if not value or value in seen[category]:
            return
        if len(found[category]) >= MAX_IOCS_PER_CATEGORY:
            return
        seen[category].add(value)
        found[category].append({"value": value, "kind": kind, "source_va": va})

    for entry in strings[:MAX_STRINGS_INSPECTED]:
        text = _entry_text(entry)
        if not text or _is_format_string(text):
            continue
        va = _entry_va(entry)
        for match in _URL.finditer(text):
            value = _trim(match.group(0))
            if _is_host(urlsplit(value).netloc):
                add(IOC_CATEGORY_URLS, value, "url", va)
        for match in _DOMAIN.finditer(text):
            value = _trim(match.group(0)).casefold()
            cloud = _cloud_kind(value)
            if cloud is not None:
                add(IOC_CATEGORY_DOMAINS, value, cloud, va)
            elif _plausible_domain(value):
                add(IOC_CATEGORY_DOMAINS, value, "domain", va)
        for match in _IPV4.finditer(text):
            value = match.group(0)
            if _valid_ipv4(value):
                kind = _cloud_kind(value) or (
                    KIND_IPV4_PRIVATE if _private_ipv4(value) else KIND_IPV4
                )
                add(IOC_CATEGORY_IPV4, value, kind, va)
        for match in _IPV6.finditer(_strip_ipv4_mapped(text)):
            parsed = _valid_ipv6(match.group(0))
            if parsed is not None:
                address = ipaddress.ip_address(parsed)
                kind = (
                    KIND_IPV6_PRIVATE
                    if address.is_private or address.is_loopback or address.is_link_local
                    else KIND_IPV6
                )
                add(IOC_CATEGORY_IPV6, parsed, kind, va)
        for match in _EMAIL.finditer(text):
            value = match.group(0)
            if _plausible_domain(value):
                add(IOC_CATEGORY_EMAILS, value, "email", va)
        for match in _REGISTRY.finditer(text):
            value = _trim(match.group(0))
            if value:
                add(IOC_CATEGORY_REGISTRY, value, "registry", va)
        for match in _DRIVE_PATH.finditer(text):
            value = _trim(match.group(0))
            if len(value) > 3:
                add(IOC_CATEGORY_FILES, value, "path", va)
        for match in _UNC_PATH.finditer(text):
            value = _trim(match.group(0))
            if value:
                add(IOC_CATEGORY_FILES, value, "unc", va)
        for value, kind in _hash_findings(text):
            add(IOC_CATEGORY_HASHES, value, kind, va)

    return found


def _import_name(entry: dict[str, Any]) -> str:
    """Return an import entry's function name, or "" when it carries none."""
    return str(entry.get("name") or "").strip()


def _capability_names(capabilities: Sequence[dict[str, Any]]) -> set[str]:
    """Return the names of a stored capability scan's entries."""
    return {
        str(entry.get("name"))
        for entry in capabilities
        if isinstance(entry, dict) and entry.get("name")
    }


def map_techniques(
    imports: Sequence[dict[str, Any]],
    capabilities: Sequence[dict[str, Any]],
    iocs: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Map imports, capabilities and IOCs onto the ATT&CK table.

    Returns one entry per technique with local evidence, sorted by id:
    ``{"id", "name", "evidence", "confidence"}``.  Evidence entries are
    ``{"kind", "value"}`` pairs of ``import``, ``capability`` or ``ioc`` kind,
    capped at :data:`MAX_EVIDENCE_PER_TECHNIQUE`.  Confidence is
    :data:`CONFIDENCE_HIGH` when an import family matched and
    :data:`CONFIDENCE_MEDIUM` when only a capability or an IOC category did.
    A technique with no evidence is left out.
    """
    import_names = [name for name in (_import_name(entry) for entry in imports) if name]
    capability_names = _capability_names(capabilities)
    results: list[dict[str, Any]] = []
    for technique in sorted(TECHNIQUES, key=lambda item: item.attack_id):
        evidence: list[dict[str, str]] = []
        matched_import = False
        for name in import_names:
            if any(pattern.search(name) for pattern in technique.imports):
                matched_import = True
                evidence.append({"kind": "import", "value": name})
        for name in technique.capabilities:
            if name in capability_names:
                evidence.append({"kind": "capability", "value": name})
        for category in technique.iocs:
            if iocs.get(category):
                evidence.append({"kind": "ioc", "value": category})
        if not evidence:
            continue
        if len(evidence) > MAX_EVIDENCE_PER_TECHNIQUE:
            evidence = evidence[:MAX_EVIDENCE_PER_TECHNIQUE]
        results.append(
            {
                "id": technique.attack_id,
                "name": technique.name,
                "evidence": evidence,
                "confidence": CONFIDENCE_HIGH if matched_import else CONFIDENCE_MEDIUM,
            }
        )
    return results


def _dict_entries(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the dict entries under *payload[key]*, ignoring any other shape."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _narrative_context(
    iocs: dict[str, list[dict[str, Any]]], techniques: list[dict[str, Any]]
) -> str:
    """Render the report's evidence as the untrusted context block for the prompt."""
    counts = ", ".join(
        f"{category}={len(iocs[category])}" for category in IOC_CATEGORIES if iocs.get(category)
    )
    listed = ", ".join(f"{item['id']} ({item['confidence']})" for item in techniques)
    lines = [f"IOC counts: {counts or 'none'}", f"ATT&CK techniques: {listed or 'none'}"]
    samples = [
        f"{category}: {', '.join(finding['value'] for finding in iocs[category][:3])}"
        for category in IOC_CATEGORIES
        if iocs.get(category)
    ]
    if samples:
        lines.append("Sample indicators: " + "; ".join(samples))
    return "\n".join(lines)


def build_threat_report(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: ThreatIO | None = None,
    llm_client: llm.LlmClient | None = None,
    narrative: bool = False,
) -> dict[str, Any]:
    """Build a binary's threat report and store it as the ``threat`` scan.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies the standalone ``rebrew strings`` and
    ``rebrew imports`` calls, and the stored ``capabilities`` scan is read, never
    run.  An unavailable engine skips both signal calls with a reason in the
    payload's ``notes`` instead of failing; so does an unavailable LLM when
    *narrative* is set.  The result carries ``binary_id``, ``iocs``,
    ``ioc_counts``, ``techniques``, ``narrative`` (``{"summary"}`` or None) and
    ``notes``.

    Raises :class:`KeyError` for an unknown binary, :class:`FileNotFoundError`
    when its row has no file on disk, and :class:`~reportal.engines.EngineError`
    when a configured engine fails.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    path = Path(str(binary["path"]))
    if not path.is_file():
        raise FileNotFoundError(f"binary {binary_id} has no file at {path}")

    notes: list[str] = []
    strings: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    source = engine if engine is not None else engines.get_engine()
    if source is None or not source.available():
        notes.append("engine-unavailable: strings and imports were not read")
    else:
        strings = _dict_entries(source.strings(path), "strings")[:MAX_STRINGS_INSPECTED]
        imports = _dict_entries(source.imports(path), "imports")

    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    stored = (
        store.get_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES) if analysis_id else None
    )
    capabilities = _dict_entries(stored or {}, "capabilities")

    iocs = extract_iocs(strings)
    techniques = map_techniques(imports, capabilities, iocs)

    summary: dict[str, Any] | None = None
    if narrative:
        client = llm_client if llm_client is not None else llm.get_client()
        if client is None or not client.available():
            notes.append("llm-unavailable: the narrative was not requested")
        else:
            try:
                summary = llm.threat_narrative(_narrative_context(iocs, techniques), client=client)
            except llm.LlmUnavailable:
                notes.append("llm-unavailable: the narrative was not requested")
            except llm.LlmError as exc:
                notes.append(f"llm-error: {exc}")

    payload = {
        "binary_id": binary_id,
        "iocs": iocs,
        "ioc_counts": {category: len(iocs[category]) for category in IOC_CATEGORIES},
        "techniques": techniques,
        "narrative": summary,
        "notes": notes,
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_THREAT,
        payload,
        params={"narrative": narrative},
    )
    return payload


# ── Software type classification ────────────────────────────────────────────
#
# The hosted portal's threat report carries a software-type badge (Trojan,
# Ransomware, ...) when its agent can classify the sample.  reportal classifies
# locally from the evidence it already holds: the stored `filetype` and
# `capabilities` scans, the stored `threat` report's techniques and indicators,
# and the stored `triage` dossier's string and DLL samples.  No model runs, no
# network call is made and the binary is never executed.
#
# Every rule in :data:`SOFTWARE_TYPE_RULES` fires on named signals, and a match
# carries the signals that produced it.  A type is a positive match: an empty
# result says nothing about whether the binary is benign.

# The closed vocabulary.  The order is the priority used to break a tie between
# two rules that fired with the same confidence.
#
# The vocabulary is deliberately short.  The hosted portal's agent also names
# Trojan, Backdoor, Spyware and Worm, and reportal does not: those labels rest
# on intent, on a remote peer or on behaviour over time, and the static
# evidence reportal holds (an import table, a string sample, a file-type
# detection) cannot tell a remote-access tool from a networked application, or
# a dropper from a text editor that writes a file.  Naming one would be a
# fabricated classification, so it is not named at all.
SOFTWARE_TYPE_RANSOMWARE = "ransomware"
SOFTWARE_TYPE_KEYLOGGER = "keylogger"
SOFTWARE_TYPE_COINMINER = "coinminer"
SOFTWARE_TYPE_DOWNLOADER = "downloader"
SOFTWARE_TYPE_INSTALLER = "installer"
SOFTWARE_TYPE_MANAGED = "managed-application"
SOFTWARE_TYPE_PACKED = "packed-executable"

SOFTWARE_TYPES: tuple[str, ...] = (
    SOFTWARE_TYPE_RANSOMWARE,
    SOFTWARE_TYPE_KEYLOGGER,
    SOFTWARE_TYPE_COINMINER,
    SOFTWARE_TYPE_DOWNLOADER,
    SOFTWARE_TYPE_INSTALLER,
    SOFTWARE_TYPE_MANAGED,
    SOFTWARE_TYPE_PACKED,
)

# Signal kinds a rule fires on.  The kind fixes the strongest confidence the
# signal can carry on its own: a matched ATT&CK technique, file-type detection,
# import, DLL or capability tag is a concrete artifact, a matched string merely
# suggests one.
SIGNAL_FILETYPE = "filetype"
SIGNAL_TECHNIQUE = "technique"
SIGNAL_IMPORT = "import"
SIGNAL_DLL = "dll"
SIGNAL_CAPABILITY = "capability"
SIGNAL_STRING = "string"

SIGNAL_CONFIDENCES: dict[str, str] = {
    SIGNAL_FILETYPE: CONFIDENCE_MEDIUM,
    SIGNAL_TECHNIQUE: CONFIDENCE_MEDIUM,
    SIGNAL_IMPORT: CONFIDENCE_MEDIUM,
    SIGNAL_DLL: CONFIDENCE_MEDIUM,
    SIGNAL_CAPABILITY: CONFIDENCE_MEDIUM,
    SIGNAL_STRING: CONFIDENCE_LOW,
}

_CONFIDENCE_RANK = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}

# Independent signal kinds a type needs before its confidence is `high`.
MIN_HIGH_CONFIDENCE_KINDS = 2

# Signals kept per type.  The full set is deduplicated first, so the cap only
# trims the rendered detail.
MAX_SIGNALS_PER_TYPE = 12

TYPE_SCOPE_NOTE = (
    "local classification over the stored filetype, capabilities, threat and triage evidence;"
    " no model and no network call"
)
TYPE_EMPTY_NOTE = (
    "no software-type rule fired; a type is a positive match, so its absence is not proof"
    " the binary is benign"
)
TYPE_CONFIDENCE_NOTE = (
    "confidence: two independent signal kinds are high; a single filetype, technique, import,"
    " DLL or capability signal is medium; a lone string match is low"
)


@dataclass(frozen=True)
class SoftwareTypeRule:
    """One software type and the local evidence that names it.

    A rule fires when any of its signals matches; ``confidence`` is the rule's
    declared ceiling, lowered to the fired signal kind's own confidence when
    only one kind matched.  A capability tag never names a type on its own,
    since a capability is a building block several types share: it is collected
    only beside a filetype, technique, import, DLL or string signal, which is
    what raises a match to :data:`CONFIDENCE_HIGH`.
    """

    software_type: str
    description: str
    confidence: str
    # Distinct non-capability signals a match needs before the rule fires.
    min_signals: int = 1
    filetype_categories: tuple[str, ...] = ()
    filetype_names: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    imports: tuple[re.Pattern[str], ...] = ()
    dlls: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()


# The rule table.  Every rule fires on evidence that is distinctive on its own:
# a crypto-encryption family, a keystroke capture pair, a mining pool, a
# download API, an installer or a runtime marker.  `min_signals` is what keeps
# a shared building block (one hook DLL, one file write) from naming a type by
# itself.  The highest-confidence match wins and a tie breaks on vocabulary
# order.
SOFTWARE_TYPE_RULES: tuple[SoftwareTypeRule, ...] = (
    SoftwareTypeRule(
        SOFTWARE_TYPE_RANSOMWARE,
        "Encrypts files and demands payment to restore them",
        CONFIDENCE_HIGH,
        techniques=("T1486",),
        imports=_patterns(
            r"^Crypt(?:Encrypt|GenKey|DeriveKey|GenRandom)",
            r"^BCryptEncrypt$",
            r"^NCryptEncrypt$",
        ),
        capabilities=("file-io", "crypto"),
        strings=_patterns(
            r"your files (?:have been|are|were) encrypted",
            r"\bransom\b",
            r"decrypt(?:ion)? (?:key|instruction|tool)",
            r"send (?:us )?bitcoin",
            r"\b(?:readme|how)[-_ ]?to[-_ ]?decrypt\b",
            r"\.locked\b",
        ),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_KEYLOGGER,
        "Captures keystrokes",
        CONFIDENCE_MEDIUM,
        min_signals=2,
        imports=_patterns(
            r"^SetWindowsHookEx",
            r"^GetAsyncKeyState$",
            r"^GetKeyboardState$",
            r"^RegisterHotKey$",
        ),
        capabilities=("ui", "registry"),
        strings=_patterns(r"\bkeylog", r"keystroke", r"key stroke"),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_COINMINER,
        "Mines cryptocurrency",
        CONFIDENCE_MEDIUM,
        capabilities=("networking", "crypto"),
        strings=_patterns(
            r"stratum\+(?:tcp|ssl)",
            r"\bxmrig\b",
            r"\bmonero\b",
            r"\bcryptonight\b",
            r"\bminergate\b",
            r"\bnicehash\b",
        ),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_DOWNLOADER,
        "Fetches a remote payload",
        CONFIDENCE_MEDIUM,
        min_signals=2,
        techniques=("T1105",),
        imports=_patterns(
            r"^URLDownloadToFile",
            r"^InternetReadFile",
            r"^WinHttpReadData$",
            r"^HttpOpenRequest",
        ),
        capabilities=("networking", "dynamic-loading"),
        strings=_patterns(r"\bGET \S* HTTP/"),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_INSTALLER,
        "Installs another program",
        CONFIDENCE_MEDIUM,
        filetype_categories=("installer",),
        filetype_names=("NSIS", "Inno Setup", "InstallShield"),
        strings=_patterns(r"Inno Setup", r"Nullsoft", r"InstallShield"),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_MANAGED,
        "Runs on a managed or bytecode runtime",
        CONFIDENCE_MEDIUM,
        filetype_names=(".NET", "Visual Basic"),
        dlls=("mscoree", "msvbvm60", "msvbvm50"),
        strings=_patterns(r"\bBSJB\b", r"\bmscorlib\b"),
    ),
    SoftwareTypeRule(
        SOFTWARE_TYPE_PACKED,
        "Carries a packed or protected image",
        CONFIDENCE_LOW,
        filetype_categories=("packer", "protector"),
        strings=_patterns(r"UPX!", r"Themida", r"VMProtect"),
    ),
)


def _entry_dicts(evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """The dict entries under ``evidence[key]``, ignoring any other shape."""
    raw = evidence.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _filetype_matches(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """The stored file-type detections the evidence carries."""
    scan = evidence.get("filetype")
    if not isinstance(scan, dict):
        return []
    raw = scan.get("matches")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _technique_ids(evidence: dict[str, Any]) -> set[str]:
    """The ATT&CK technique ids the stored threat report mapped."""
    return {
        str(entry.get("id")) for entry in _entry_dicts(evidence, "techniques") if entry.get("id")
    }


def _evidence_capabilities(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """The capability entries the evidence carries."""
    return _entry_dicts(evidence, "capabilities")


def _triage_dlls(triage: Any) -> list[str]:
    """The DLL names a stored triage dossier reports."""
    if not isinstance(triage, dict):
        return []
    section = triage.get("imports")
    if not isinstance(section, dict):
        return []
    raw = section.get("dlls")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, str) and item]


def _triage_strings(triage: Any) -> list[str]:
    """The sampled string texts a stored triage dossier reports."""
    if not isinstance(triage, dict):
        return []
    section = triage.get("strings")
    if not isinstance(section, dict):
        return []
    raw = section.get("top")
    if not isinstance(raw, list):
        return []
    texts: list[str] = []
    for entry in raw:
        if isinstance(entry, str) and entry:
            texts.append(entry)
        elif isinstance(entry, dict):
            text = entry.get("text")
            if isinstance(text, str) and text:
                texts.append(text)
    return texts


def _evidence_dlls(evidence: dict[str, Any]) -> list[str]:
    """Every DLL name the evidence carries, in order."""
    names: list[str] = []
    for entry in _entry_dicts(evidence, "imports"):
        dll = entry.get("dll")
        if isinstance(dll, str) and dll:
            names.append(dll)
    explicit = evidence.get("dlls")
    if isinstance(explicit, list):
        names.extend(item for item in explicit if isinstance(item, str) and item)
    names.extend(_triage_dlls(evidence.get("triage")))
    return names


def _evidence_strings(evidence: dict[str, Any]) -> list[str]:
    """Every string text the evidence carries, capped at :data:`MAX_STRINGS_INSPECTED`."""
    texts: list[str] = []
    for entry in _entry_dicts(evidence, "strings")[:MAX_STRINGS_INSPECTED]:
        text = entry.get("text")
        if isinstance(text, str) and text:
            texts.append(text)
    raw = evidence.get("strings")
    if isinstance(raw, list):
        texts.extend(item for item in raw[:MAX_STRINGS_INSPECTED] if isinstance(item, str) and item)
    texts.extend(_triage_strings(evidence.get("triage")))
    return texts


def _import_names(evidence: dict[str, Any]) -> list[str]:
    """Every import function name the evidence carries, in order."""
    return [
        name
        for name in (_import_name(entry) for entry in _entry_dicts(evidence, "imports"))
        if name
    ]


def _filetype_signal(entry: dict[str, Any]) -> str:
    """Render a file-type detection as one signal value."""
    name = str(entry.get("name", ""))
    category = str(entry.get("category", ""))
    confidence = str(entry.get("confidence", ""))
    return f"{name} ({category}, {confidence})"


def _software_signals(
    rule: SoftwareTypeRule,
    *,
    filetype: Sequence[dict[str, Any]],
    techniques: set[str],
    imports: Sequence[str],
    dlls: Sequence[str],
    capabilities: set[str],
    strings: Sequence[str],
) -> list[dict[str, str]]:
    """The deduplicated signals *rule* fires over one evidence set."""
    signals: list[dict[str, str]] = []
    for entry in filetype:
        category = str(entry.get("category", ""))
        name = str(entry.get("name", ""))
        if category in rule.filetype_categories or name in rule.filetype_names:
            signals.append({"kind": SIGNAL_FILETYPE, "value": _filetype_signal(entry)})
    for technique_id in sorted(techniques):
        if technique_id in rule.techniques:
            signals.append({"kind": SIGNAL_TECHNIQUE, "value": technique_id})
    for name in imports:
        if any(pattern.search(name) for pattern in rule.imports):
            signals.append({"kind": SIGNAL_IMPORT, "value": name})
    for name in dlls:
        if any(_dll_matches(name, expected) for expected in rule.dlls):
            signals.append({"kind": SIGNAL_DLL, "value": name})
    for name in sorted(capabilities):
        if name in rule.capabilities:
            signals.append({"kind": SIGNAL_CAPABILITY, "value": name})
    for text in strings:
        if any(pattern.search(text) for pattern in rule.strings):
            signals.append({"kind": SIGNAL_STRING, "value": text})
    return _dedupe_signals(signals)[:MAX_SIGNALS_PER_TYPE]


def _dedupe_signals(signals: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Collapse repeated ``(kind, value)`` signals, keeping the first."""
    seen: set[tuple[str, str]] = set()
    distinct: list[dict[str, str]] = []
    for signal in signals:
        key = (signal["kind"], signal["value"])
        if key in seen:
            continue
        seen.add(key)
        distinct.append(signal)
    return distinct


def _dll_matches(name: str, expected: str) -> bool:
    """True when DLL *name* is *expected*, ignoring case and a ``.dll`` suffix."""
    return name.strip().casefold().removesuffix(".dll") == expected.strip().casefold().removesuffix(
        ".dll"
    )


def _names_a_type(rule: SoftwareTypeRule, signals: Sequence[dict[str, str]]) -> bool:
    """True when *signals* carry what *rule* needs to fire.

    A capability tag is a building block several types share, so it never names
    a type on its own and never counts toward :attr:`SoftwareTypeRule.min_signals`.
    """
    primary = {signal["value"] for signal in signals if signal["kind"] != SIGNAL_CAPABILITY}
    return len(primary) >= rule.min_signals


def _type_confidence(rule: SoftwareTypeRule, signals: Sequence[dict[str, str]]) -> str:
    """Derive a type match's confidence from its fired signal kinds."""
    kinds = {signal["kind"] for signal in signals}
    if len(kinds) >= MIN_HIGH_CONFIDENCE_KINDS:
        return CONFIDENCE_HIGH
    ceiling = SIGNAL_CONFIDENCES[signals[0]["kind"]]
    return max((rule.confidence, ceiling), key=lambda level: _CONFIDENCE_RANK[level])


def evidence_sources(evidence: dict[str, Any]) -> list[str]:
    """The stored scans that carry data, in a stable order.

    A scan that ran and found nothing is not a source: it carries no evidence
    for the classifier to read or the score to aggregate, which is what keeps
    an empty result an explicit ``null`` rather than a zero.
    """
    sources: list[str] = []
    if _filetype_matches(evidence):
        sources.append("filetype")
    if _entry_dicts(evidence, "capabilities"):
        sources.append("capabilities")
    if _technique_ids(evidence) or any(_ioc_lists(evidence).values()):
        sources.append("threat")
    triage = evidence.get("triage")
    if _triage_strings(triage) or _triage_dlls(triage):
        sources.append("triage")
    return sources


def classify_software(evidence: dict[str, Any]) -> dict[str, Any]:
    """Name the software type *evidence* supports, with the signals that fired.

    *evidence* carries the stored scans: ``filetype`` (the file-type detection
    result), ``capabilities`` (its capability entries), ``techniques`` and
    ``iocs`` (the stored threat report's), ``imports`` (an import table),
    ``strings`` (string entries) and ``triage`` (the stored dossier, whose
    string and DLL samples are used).  A missing piece simply disables the
    rules that need it.

    Returns ``{"type", "description", "confidence", "signals",
    "evidence_sources", "notes"}``.  The type is the highest-confidence match,
    a tie breaking on :data:`SOFTWARE_TYPES` order; ``type`` is ``None`` when
    no rule fired, because a type is a positive match and its absence proves
    nothing.
    """
    filetype = _filetype_matches(evidence)
    techniques = _technique_ids(evidence)
    imports = _import_names(evidence)
    dlls = _evidence_dlls(evidence)
    capabilities = _capability_names(_evidence_capabilities(evidence))
    strings = _evidence_strings(evidence)

    candidates: list[tuple[int, SoftwareTypeRule, list[dict[str, str]]]] = []
    for rule in SOFTWARE_TYPE_RULES:
        signals = _software_signals(
            rule,
            filetype=filetype,
            techniques=techniques,
            imports=imports,
            dlls=dlls,
            capabilities=capabilities,
            strings=strings,
        )
        if not _names_a_type(rule, signals):
            continue
        candidates.append((_CONFIDENCE_RANK[_type_confidence(rule, signals)], rule, signals))

    sources = evidence_sources(evidence)
    if not candidates:
        return {
            "type": None,
            "description": None,
            "confidence": None,
            "signals": [],
            "evidence_sources": sources,
            "notes": [TYPE_SCOPE_NOTE, TYPE_CONFIDENCE_NOTE, TYPE_EMPTY_NOTE],
        }
    # The rules are declared in vocabulary order, so `min` keeps the first of
    # two equally confident matches.
    _rank, rule, signals = min(candidates, key=lambda item: item[0])
    return {
        "type": rule.software_type,
        "description": rule.description,
        "confidence": _type_confidence(rule, signals),
        "signals": signals,
        "evidence_sources": sources,
        "notes": [TYPE_SCOPE_NOTE, TYPE_CONFIDENCE_NOTE],
    }


# ── Threat score ────────────────────────────────────────────────────────────
#
# One 0-100 number for the binary, aggregated from the same stored evidence the
# classifier reads.  Every contribution is named in the payload with the points
# it added and the evidence behind them, so the number is never bare.  The
# weights are reportal's own: the hosted portal publishes no scale, and its
# score comes from a model reportal does not run.

CONTRIBUTION_PACKING = "packing"
CONTRIBUTION_CAPABILITIES = "capabilities"
CONTRIBUTION_INDICATORS = "indicators"
CONTRIBUTION_TECHNIQUES = "techniques"

# Points a matched file-type detection adds.  A packer and a protector overlap
# in meaning, so the whole contribution is capped instead of counting wild.
PACKER_POINTS = 10
PROTECTOR_POINTS = 15
MAX_PACKING_POINTS = 20

# Points a capability tag adds.  An unlisted tag (a third-party capability)
# takes the default, so it is scored rather than silently dropped.
CAPABILITY_POINTS: dict[str, int] = {
    "networking": 6,
    "persistence": 10,
    "process-execution": 4,
    "memory": 8,
    "threading": 3,
    "registry": 4,
    "crypto": 5,
    "anti-debug": 8,
    "dynamic-loading": 5,
    "file-io": 2,
    "compression": 2,
    "synchronization": 1,
    "ui": 1,
    "console": 1,
}
DEFAULT_CAPABILITY_POINTS = 2
MAX_CAPABILITY_POINTS = 30

# Points one non-empty IOC category adds, whatever the category's count.
IOC_POINTS: dict[str, int] = {
    IOC_CATEGORY_URLS: 8,
    IOC_CATEGORY_DOMAINS: 5,
    IOC_CATEGORY_IPV4: 5,
    IOC_CATEGORY_IPV6: 5,
    IOC_CATEGORY_EMAILS: 3,
    IOC_CATEGORY_REGISTRY: 3,
    IOC_CATEGORY_FILES: 2,
    IOC_CATEGORY_HASHES: 1,
}
DEFAULT_IOC_POINTS = 1
MAX_INDICATOR_POINTS = 25

# Points an ATT&CK technique adds, by the confidence the mapping gave it.
TECHNIQUE_POINTS: dict[str, int] = {CONFIDENCE_HIGH: 10, CONFIDENCE_MEDIUM: 5}
DEFAULT_TECHNIQUE_POINTS = 2
MAX_TECHNIQUE_POINTS = 30

# The scale.  A score at or above a band's floor reads as that band; the bands
# are reportal's own and are stated in every payload.
SCORE_MAX = 100
SCORE_BAND_LOW = "low"
SCORE_BAND_MODERATE = "moderate"
SCORE_BAND_HIGH = "high"
SCORE_BAND_CRITICAL = "critical"
SCORE_MODERATE_FLOOR = 25
SCORE_HIGH_FLOOR = 50
SCORE_CRITICAL_FLOOR = 75

# Evidence entries named per contribution.  The points are summed over the full
# set first, so the cap only trims the rendered detail.
MAX_EVIDENCE_PER_CONTRIBUTION = 8

SCORE_SCOPE_NOTE = (
    "reportal's own deterministic heuristic over the stored scans, not the hosted"
    " portal's model score"
)
SCORE_SCALE_NOTE = (
    "0-100: 1-24 low, 25-49 moderate, 50-74 high, 75-100 critical; every contribution's"
    " points are named in this payload"
)
SCORE_EMPTY_NOTE = (
    "no stored scan carries any evidence to score, so the score is null rather than a zero"
)


def _contribution(name: str, points: int, evidence: Sequence[str]) -> dict[str, Any]:
    """One named contribution, its points and the evidence behind them."""
    return {
        "name": name,
        "points": points,
        "evidence": list(evidence)[:MAX_EVIDENCE_PER_CONTRIBUTION],
    }


def _packing_contribution(filetype: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """The packing contribution from the stored packer and protector matches."""
    points = 0
    evidence: list[str] = []
    for entry in filetype:
        category = str(entry.get("category", ""))
        if category == "packer":
            points += PACKER_POINTS
        elif category == "protector":
            points += PROTECTOR_POINTS
        else:
            continue
        evidence.append(_filetype_signal(entry))
    if not evidence:
        return None
    return _contribution(CONTRIBUTION_PACKING, min(points, MAX_PACKING_POINTS), evidence)


def _capability_contribution(capabilities: set[str]) -> dict[str, Any] | None:
    """The capability contribution from the stored capability tags."""
    if not capabilities:
        return None
    points = 0
    for name in sorted(capabilities):
        points += CAPABILITY_POINTS.get(name, DEFAULT_CAPABILITY_POINTS)
    return _contribution(
        CONTRIBUTION_CAPABILITIES, min(points, MAX_CAPABILITY_POINTS), sorted(capabilities)
    )


def _indicator_contribution(iocs: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    """The indicator contribution from the stored report's IOC categories.

    The known categories come first in :data:`IOC_CATEGORIES` order; a category
    a future payload adds takes the default points rather than being dropped.
    """
    evidence: list[str] = []
    points = 0
    extra = sorted(category for category in iocs if category not in IOC_CATEGORIES)
    for category in [*IOC_CATEGORIES, *extra]:
        findings = iocs.get(category)
        if not findings:
            continue
        points += IOC_POINTS.get(category, DEFAULT_IOC_POINTS)
        evidence.append(f"{category}: {len(findings)}")
    if not evidence:
        return None
    return _contribution(CONTRIBUTION_INDICATORS, min(points, MAX_INDICATOR_POINTS), evidence)


def _technique_contribution(techniques: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """The technique contribution from the stored report's ATT&CK rows."""
    evidence: list[str] = []
    points = 0
    for entry in techniques:
        technique_id = str(entry.get("id", ""))
        if not technique_id:
            continue
        confidence = str(entry.get("confidence", ""))
        points += TECHNIQUE_POINTS.get(confidence, DEFAULT_TECHNIQUE_POINTS)
        evidence.append(f"{technique_id} ({confidence or 'unrated'})")
    if not evidence:
        return None
    return _contribution(CONTRIBUTION_TECHNIQUES, min(points, MAX_TECHNIQUE_POINTS), evidence)


def score_band(score: int) -> str:
    """The band a 0-100 *score* reads as."""
    if score >= SCORE_CRITICAL_FLOOR:
        return SCORE_BAND_CRITICAL
    if score >= SCORE_HIGH_FLOOR:
        return SCORE_BAND_HIGH
    if score >= SCORE_MODERATE_FLOOR:
        return SCORE_BAND_MODERATE
    return SCORE_BAND_LOW


def score_threat(evidence: dict[str, Any]) -> dict[str, Any]:
    """Aggregate a 0-100 threat score from the same evidence the classifier reads.

    Returns ``{"score", "max", "band", "contributions", "evidence_sources",
    "notes"}``.  Each contribution is ``{"name", "points", "evidence"}``, so the
    number always arrives with what produced it.  ``score`` is ``None`` when no
    evidence source carries anything, because a score over nothing would read as
    a harmless zero; a source that carries evidence but scores no points is a
    real zero and says so.
    """
    sources = evidence_sources(evidence)
    contributions = [
        entry
        for entry in (
            _packing_contribution(_filetype_matches(evidence)),
            _capability_contribution(_capability_names(_evidence_capabilities(evidence))),
            _indicator_contribution(_ioc_lists(evidence)),
            _technique_contribution(_entry_dicts(evidence, "techniques")),
        )
        if entry is not None
    ]
    if not sources:
        return {
            "score": None,
            "max": SCORE_MAX,
            "band": None,
            "contributions": [],
            "evidence_sources": [],
            "notes": [SCORE_SCOPE_NOTE, SCORE_SCALE_NOTE, SCORE_EMPTY_NOTE],
        }
    total = min(SCORE_MAX, sum(int(entry["points"]) for entry in contributions))
    return {
        "score": total,
        "max": SCORE_MAX,
        "band": score_band(total),
        "contributions": contributions,
        "evidence_sources": sources,
        "notes": [SCORE_SCOPE_NOTE, SCORE_SCALE_NOTE],
    }


def _ioc_lists(evidence: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The indicator lists the evidence carries, ignoring any other shape."""
    raw = evidence.get("iocs")
    if not isinstance(raw, dict):
        return {}
    lists: dict[str, list[dict[str, Any]]] = {}
    for category, entries in raw.items():
        if isinstance(entries, list):
            lists[str(category)] = [entry for entry in entries if isinstance(entry, dict)]
    return lists


def stored_evidence(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Assemble the classification evidence reportal already stores.

    Reads the binary's newest analysis and the ``filetype``, ``capabilities``,
    ``threat`` and ``triage`` scans on it.  A binary with no analysis, or one
    whose scans were never run, carries empty evidence and no engine call is
    made.
    """
    evidence: dict[str, Any] = {
        "filetype": {},
        "capabilities": [],
        "imports": [],
        "strings": [],
        "iocs": {},
        "techniques": [],
        "triage": {},
    }
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return evidence
    filetype = store.get_scan(conn, analysis_id, store.SCAN_KIND_FILETYPE)
    if isinstance(filetype, dict):
        evidence["filetype"] = filetype
    capabilities = store.get_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES)
    if isinstance(capabilities, dict):
        evidence["capabilities"] = _dict_entries(capabilities, "capabilities")
    threat_scan = store.get_scan(conn, analysis_id, store.SCAN_KIND_THREAT)
    if isinstance(threat_scan, dict):
        evidence["iocs"] = threat_scan.get("iocs") or {}
        evidence["techniques"] = _dict_entries(threat_scan, "techniques")
    triage = store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE)
    if isinstance(triage, dict):
        evidence["triage"] = triage
    return evidence


def classify_binary(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The software type and the threat score for *binary_id*'s stored evidence.

    Returns ``{"software_type", "threat_score"}``, the two keys the threat and
    triage payloads carry.  Both are derived from the same evidence set at call
    time, so every surface answers the same value for the same stored state,
    and neither runs the engine or the model.
    """
    evidence = stored_evidence(conn, binary_id)
    return {
        "software_type": classify_software(evidence),
        "threat_score": score_threat(evidence),
    }

"""Deterministic secrets scan: credential patterns plus entropy.

The hosted RevEng.AI portal recovers hardcoded secrets and keys with a model.
reportal reproduces that half locally and deterministically: the strings
``rebrew strings`` already returns are matched against the fixed pattern table
in :data:`SECRET_PATTERNS` and checked for high-entropy blobs, so a scan needs
no LLM and makes no network call.

Findings are sensitive.  Each one carries the raw ``value`` for a caller that
asked for it plus a ``redacted`` form for display, and :func:`run_secrets`
stores both locally as the ``secrets`` scan.

Rule choices, all on the conservative side:

* A pattern matches the credential shape itself, never a bare word: the
  generic assignment rule needs a quoted literal of at least
  :data:`MIN_LITERAL_LENGTH` characters, and the AWS secret access key is
  anchored on its config key so an arbitrary 40-character base64 blob is not
  reported as a key.
* Entropy detection requires a mixed character class (a letter plus a digit or
  base64 punctuation) and no whitespace, so an English sentence, a dotted
  version string and a long lowercase dictionary word do not qualify.  A hex
  blob of even length is recognized separately with a slightly lower floor,
  since the hexadecimal alphabet carries at most four bits per character.
* A value found more than once collapses to one finding that keeps the highest
  confidence and the first VA.
"""

from __future__ import annotations

import math
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from reportal import capabilities, engines, store, threat

# Findings kept in a payload.  The full set is deduplicated first and the exact
# counts (`count`, `by_confidence`) are computed over it, so the cap only trims
# the rendered detail.
MAX_FINDINGS = 50

# Strings inspected by one scan.  The engine can return tens of thousands and
# every pattern regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Confidence labels, matching the other local scans: a specific credential
# shape is `high`, a generic assignment or an entropy blob is `medium`.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"

# Sort rank per confidence; lower sorts first so specific shapes lead the list.
_CONFIDENCE_RANK = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1}

# Finding kinds: a pattern-table match, a high-entropy blob, or an embedded
# staged payload (a blob large enough to be a second stage, not a key).
KIND_PATTERN = "pattern"
KIND_ENTROPY = "entropy"
KIND_PAYLOAD = "embedded-payload"

# Name an entropy finding carries; it is not a pattern-table name.
ENTROPY_NAME = "high-entropy"

# Name a staged-payload finding carries.
PAYLOAD_NAME = "embedded-payload"

# Characters kept at each end of a redacted value.
REDACT_PREFIX_CHARS = 4
REDACT_SUFFIX_CHARS = 4

# Shortest value the entropy check considers, and the Shannon bits per
# character a general mixed-class value must reach.  A hex blob has its own,
# slightly lower floor, since the hexadecimal alphabet carries at most four
# bits per character; the floor stays above ``log2(10)``, so a digits-only
# string (a serial number, say) never qualifies.
MIN_ENTROPY_LENGTH = 20
MIN_ENTROPY_BITS = 3.5
HEX_MIN_ENTROPY_BITS = 3.4

# Length at or above which a high-entropy base64-shaped value stops being a
# key and starts being a staged second stage (the LinPEAS-dropper shape:
# a base64 blob decoded and piped to a shell at runtime).  Well above any
# API key or token, comfortably below a real staged script.
MIN_PAYLOAD_LENGTH = 4096

# Shortest quoted literal the generic assignment rule accepts.
MIN_LITERAL_LENGTH = 8

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")

# Base64 punctuation, including the URL-safe spelling.  A value needs a letter
# plus one of these (or a digit) before its entropy is considered.
_BASE64_PUNCTUATION = frozenset("+/=_-")


@dataclass(frozen=True)
class SecretPattern:
    """One credential pattern: its label, matcher, confidence and description.

    A match reports the named ``value`` group when the pattern carries one, so
    a context-anchored pattern such as the AWS secret access key or the
    connection-string rule reports the credential rather than the whole match.
    """

    name: str
    pattern: re.Pattern[str]
    confidence: str
    description: str


def _pattern(value: str) -> re.Pattern[str]:
    return re.compile(value)


# The pattern table.  Specific credential shapes are `high` confidence; the
# generic assignment rule and the connection-string rule are `medium`, since
# they key on a nearby label rather than on a self-identifying format.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        name="aws-access-key-id",
        pattern=_pattern(r"\bAKIA[0-9A-Z]{16}\b"),
        confidence=CONFIDENCE_HIGH,
        description="AWS access key id",
    ),
    SecretPattern(
        name="aws-secret-access-key",
        pattern=_pattern(
            r"(?i)\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key"
            r"|aws[_-]?secret[_-]?key)\b\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9/+=]{40})[\"']?"
        ),
        confidence=CONFIDENCE_HIGH,
        description="AWS secret access key, anchored on its config key",
    ),
    SecretPattern(
        name="google-api-key",
        pattern=_pattern(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        confidence=CONFIDENCE_HIGH,
        description="Google API key",
    ),
    SecretPattern(
        name="github-token",
        pattern=_pattern(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        confidence=CONFIDENCE_HIGH,
        description="GitHub token",
    ),
    SecretPattern(
        name="slack-token",
        pattern=_pattern(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}"),
        confidence=CONFIDENCE_HIGH,
        description="Slack token",
    ),
    SecretPattern(
        name="stripe-key",
        pattern=_pattern(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        confidence=CONFIDENCE_HIGH,
        description="Stripe live or test key",
    ),
    SecretPattern(
        name="openai-api-key",
        pattern=_pattern(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        confidence=CONFIDENCE_HIGH,
        description="OpenAI-style sk- key",
    ),
    SecretPattern(
        name="jwt",
        pattern=_pattern(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{10,}"),
        confidence=CONFIDENCE_HIGH,
        description="JSON Web Token",
    ),
    SecretPattern(
        name="pem-private-key",
        pattern=_pattern(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        confidence=CONFIDENCE_HIGH,
        description="PEM private key header",
    ),
    SecretPattern(
        name="connection-string",
        pattern=_pattern(
            r"(?i)\b(?:server|data source|data src|address|addr|network address)\s*="
            r"\s*[^;\"'\r\n]{1,128};[^\r\n]*?\b(?:password|pwd)\s*="
            r"\s*(?P<value>[^;\"'\r\n]{1,128})"
        ),
        confidence=CONFIDENCE_MEDIUM,
        description="Password embedded in a database connection string",
    ),
    SecretPattern(
        name="generic-assignment",
        pattern=_pattern(
            rf"(?i)\b[a-z0-9_]*(?:password|passwd|secret|api_?key|access_key|token)"
            rf"\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]{{{MIN_LITERAL_LENGTH},}})[\"']"
        ),
        confidence=CONFIDENCE_MEDIUM,
        description="Quoted literal assigned to a credential-named field",
    ),
)


def entropy(value: str) -> float:
    """Shannon entropy of *value* in bits per character.

    An empty value has no entropy, so it returns ``0.0`` rather than raising.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_hex_blob(value: str) -> bool:
    """True when *value* is a whole number of hexadecimal bytes."""
    return bool(value) and len(value) % 2 == 0 and all(c in _HEX_CHARS for c in value)


def _is_mixed_class(value: str) -> bool:
    """True when *value* has a letter plus a digit or base64 punctuation."""
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    has_punctuation = any(character in _BASE64_PUNCTUATION for character in value)
    return has_letter and (has_digit or has_punctuation)


def looks_high_entropy(
    value: str,
    *,
    min_length: int = MIN_ENTROPY_LENGTH,
    min_entropy: float = MIN_ENTROPY_BITS,
) -> bool:
    """True when *value* looks like a key-sized high-entropy blob.

    A value shorter than *min_length* is rejected outright.  A hexadecimal blob
    of even length is graded against :data:`HEX_MIN_ENTROPY_BITS`.  Anything
    else needs the mixed character class and no whitespace, then *min_entropy*
    bits per character.
    """
    if len(value) < min_length:
        return False
    if _is_hex_blob(value):
        return entropy(value) >= HEX_MIN_ENTROPY_BITS
    if any(character.isspace() for character in value):
        return False
    if not _is_mixed_class(value):
        return False
    return entropy(value) >= min_entropy


_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def looks_staged_payload(value: str) -> bool:
    """True when *value* looks like an embedded staged second stage.

    A base64-shaped run at or above :data:`MIN_PAYLOAD_LENGTH` with no
    whitespace: far too large for a key or token, the shape of a script
    blob a dropper decodes and pipes to a shell at runtime.
    """
    if len(value) < MIN_PAYLOAD_LENGTH:
        return False
    if any(character.isspace() for character in value):
        return False
    return all(character in _BASE64_CHARS for character in value)


def redact(value: str) -> str:
    """Mask all but the first and last :data:`REDACT_PREFIX_CHARS` characters.

    A value too short to keep both ends is masked whole, so a short secret is
    not partly revealed.
    """
    if len(value) <= REDACT_PREFIX_CHARS + REDACT_SUFFIX_CHARS:
        return "*" * len(value)
    middle = len(value) - REDACT_PREFIX_CHARS - REDACT_SUFFIX_CHARS
    return f"{value[:REDACT_PREFIX_CHARS]}{'*' * middle}{value[-REDACT_SUFFIX_CHARS:]}"


def _matched_value(match: re.Match[str]) -> str:
    """Return the credential a match carries: its ``value`` group, else the match."""
    return match.groupdict().get("value") or match.group(0)


def _va_sort_key(va: int | None) -> int:
    """Sort key for a finding's VA, placing a VA-less finding first."""
    return -1 if va is None else va


def _add(
    findings: dict[str, dict[str, Any]],
    *,
    kind: str,
    name: str,
    value: str,
    va: int | None,
    confidence: str,
) -> None:
    """Record one match, collapsing a repeat of the same *value*.

    The first VA wins.  A later match replaces the recorded kind, name and
    confidence only when it is more confident, so a value that is both a
    specific shape and an entropy blob keeps the shape.
    """
    existing = findings.get(value)
    if existing is None:
        findings[value] = {
            "kind": kind,
            "name": name,
            "value": value,
            "redacted": redact(value),
            "va": va,
            "confidence": confidence,
        }
        return
    if _CONFIDENCE_RANK[confidence] < _CONFIDENCE_RANK[existing["confidence"]]:
        existing["kind"] = kind
        existing["name"] = name
        existing["confidence"] = confidence


def scan_secrets(strings: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Scan engine string entries for credentials and high-entropy values.

    Returns ``{"findings", "count", "by_confidence"}``.  A finding is
    ``{"kind", "name", "value", "redacted", "va", "confidence"}``, where ``kind``
    is ``pattern``, ``entropy`` or ``embedded-payload``, ``va`` is the entry's
    VA when it carries one, and ``redacted`` is the value with its middle
    masked.  Findings deduplicate by value, keeping the highest confidence
    and the first VA; the list sorts by confidence, then name, then VA;
    ``count`` and ``by_confidence`` stay exact while the list itself is
    capped at :data:`MAX_FINDINGS`.
    """
    findings: dict[str, dict[str, Any]] = {}
    for entry in strings[:MAX_STRINGS_INSPECTED]:
        text = capabilities._string_text(entry)
        if not text:
            continue
        va = threat._entry_va(entry)
        for secret in SECRET_PATTERNS:
            for match in secret.pattern.finditer(text):
                value = _matched_value(match)
                if not value:
                    continue
                _add(
                    findings,
                    kind=KIND_PATTERN,
                    name=secret.name,
                    value=value,
                    va=va,
                    confidence=secret.confidence,
                )
        if looks_staged_payload(text):
            _add(
                findings,
                kind=KIND_PAYLOAD,
                name=PAYLOAD_NAME,
                value=text,
                va=va,
                confidence=CONFIDENCE_MEDIUM,
            )
        elif looks_high_entropy(text):
            _add(
                findings,
                kind=KIND_ENTROPY,
                name=ENTROPY_NAME,
                value=text,
                va=va,
                confidence=CONFIDENCE_MEDIUM,
            )

    ordered = sorted(
        findings.values(),
        key=lambda finding: (
            _CONFIDENCE_RANK[finding["confidence"]],
            finding["name"],
            _va_sort_key(finding["va"]),
        ),
    )
    by_confidence = {
        CONFIDENCE_HIGH: sum(1 for finding in ordered if finding["confidence"] == CONFIDENCE_HIGH),
        CONFIDENCE_MEDIUM: sum(
            1 for finding in ordered if finding["confidence"] == CONFIDENCE_MEDIUM
        ),
    }
    return {
        "findings": ordered[:MAX_FINDINGS],
        "count": len(ordered),
        "by_confidence": by_confidence,
    }


def run_secrets(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: capabilities.StringsIO | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Scan a binary's strings for secrets and store the result.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies the standalone ``rebrew strings`` call.
    *strings* overrides the engine payload outright, which is how tests keep the
    run hermetic.  Strings are capped at :data:`MAX_STRINGS_INSPECTED`.

    Raises :class:`KeyError` for an unknown binary and
    :class:`FileNotFoundError` when its row has no file on disk; an engine
    failure propagates.  Returns ``{"binary_id", "findings", "count",
    "by_confidence", "scanned"}``, where ``scanned`` is the number of strings
    examined.  An empty ``findings`` is a valid result.
    """
    _binary, path = capabilities.require_binary_file(conn, binary_id)
    source: capabilities.StringsIO = engine if engine is not None else engines.get_engine()
    examined = capabilities.load_strings(path, source, strings=strings)
    payload = {"binary_id": binary_id, **scan_secrets(examined), "scanned": len(examined)}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_SECRETS, payload)
    return payload

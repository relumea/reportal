"""Tests for reportal.secrets: the pattern table, entropy rules and the scan."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import engines, secrets, store
from reportal.secrets import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    HEX_MIN_ENTROPY_BITS,
    MAX_FINDINGS,
    MAX_STRINGS_INSPECTED,
    MIN_ENTROPY_BITS,
    MIN_ENTROPY_LENGTH,
    MIN_LITERAL_LENGTH,
    MIN_PAYLOAD_LENGTH,
    SECRET_PATTERNS,
)

# Realistic samples per family, plus the near-miss each rule must reject.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_ACCESS_KEY_SHORT = "AKIAIOSFODNN7EXAMPL"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SECRET_ASSIGNMENT = f"aws_secret_access_key={AWS_SECRET}"
BARE_BASE64 = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo"
GOOGLE_KEY = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
GOOGLE_KEY_SHORT = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBW"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
GITHUB_TOKEN_SHORT = "ghp_1234567890abcdefghijklmnopqrstuvwxy"
GITHUB_PAT = "github_pat_" + "A" * 22
GITHUB_PAT_SHORT = "github_pat_" + "A" * 21
SLACK_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwxyz"
SLACK_TOKEN_MISS = "xoxz-123456789012-1234567890123"
STRIPE_KEY = "sk_live_51H8Q2eKZabcdefghijklmnop"
STRIPE_KEY_SHORT = "sk_live_short"
OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
OPENAI_KEY_SHORT = "sk-short"
ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345"
ANTHROPIC_KEY_SHORT = "sk-ant-short"
DISCORD_TOKEN = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Gabcde.abcdefghijklmnopqrstuvwxyz012"
DISCORD_TOKEN_MISS = "XTIzNDU2Nzg5MDEyMzQ1Njc4.Gabcde.abcdefghijklmnopqrstuvwxyz012"
TELEGRAM_TOKEN = "123456789:AAEabcdefghijklmnopqrstuvwxyz012345"
TELEGRAM_TOKEN_MISS = "123456789:BBabcdefghijklmnopqrstuvwxyz012345"
NPM_TOKEN = "npm_abcdefghijklmnopqrstuvwxyz0123456789"
NPM_TOKEN_SHORT = "npm_abcdefghijklmnopqrstuvwxyz012345678"
GITLAB_TOKEN = "glpat-abcdefghijklmnopqrst"
GITLAB_TOKEN_SHORT = "glpat-abcdefghijklmnopqrs"
HF_TOKEN = "hf_" + "a" * 34
HF_TOKEN_SHORT = "hf_" + "a" * 33
SENDGRID_KEY = "SG." + "A" * 22 + "." + "B" * 43
SENDGRID_KEY_MISS = "SG." + "A" * 22 + "." + "B" * 20
TWILIO_SID = "AC" + "a" * 32
TWILIO_SID_MISS = "AC" + "A" * 32
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
JWT_TWO_PARTS = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"
PEM_KEY = "-----BEGIN RSA PRIVATE KEY-----"
PEM_KEY_MISS = "-----BEGIN PUBLIC KEY-----"
CONNECTION_STRING = "Server=db.example.com;Database=app;User Id=admin;Password=s3cr3tP@ssw0rd;"
CONNECTION_PASSWORD = "s3cr3tP@ssw0rd"
CONNECTION_STRING_MISS = "Server=db.example.com;Database=app;User Id=admin;"
PASSWORD_ASSIGNMENT = 'password = "hunter2hunter2"'
PASSWORD_ASSIGNMENT_SHORT = 'password = "short"'
PASSWORD_ASSIGNMENT_UNQUOTED = "password=hunter2hunter2"

# Entropy samples: two positives and the shapes that must not qualify.
BASE64_BLOB = "aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW6xY9zA2bC5d=="
HEX_BLOB = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
ENGLISH_SENTENCE = "The quick brown fox jumps over the lazy dog."
DOTTED_VERSION = "1.2.3.4.5.6.7.8.9.10"
DICTIONARY_WORD = "antidisestablishmentarianism"

POSITIVE_CASES = [
    ("aws-access-key-id", AWS_ACCESS_KEY, AWS_ACCESS_KEY),
    ("aws-secret-access-key", AWS_SECRET_ASSIGNMENT, AWS_SECRET),
    ("google-api-key", GOOGLE_KEY, GOOGLE_KEY),
    ("github-token", GITHUB_TOKEN, GITHUB_TOKEN),
    ("github-token", GITHUB_PAT, GITHUB_PAT),
    ("slack-token", SLACK_TOKEN, SLACK_TOKEN),
    ("stripe-key", STRIPE_KEY, STRIPE_KEY),
    ("openai-api-key", OPENAI_KEY, OPENAI_KEY),
    ("anthropic-api-key", ANTHROPIC_KEY, ANTHROPIC_KEY),
    ("discord-bot-token", DISCORD_TOKEN, DISCORD_TOKEN),
    ("telegram-bot-token", TELEGRAM_TOKEN, TELEGRAM_TOKEN),
    ("npm-token", NPM_TOKEN, NPM_TOKEN),
    ("gitlab-token", GITLAB_TOKEN, GITLAB_TOKEN),
    ("huggingface-token", HF_TOKEN, HF_TOKEN),
    ("sendgrid-key", SENDGRID_KEY, SENDGRID_KEY),
    ("twilio-account-sid", TWILIO_SID, TWILIO_SID),
    ("jwt", JWT, JWT),
    ("pem-private-key", PEM_KEY, PEM_KEY),
    ("connection-string", CONNECTION_STRING, CONNECTION_PASSWORD),
    ("generic-assignment", PASSWORD_ASSIGNMENT, "hunter2hunter2"),
]

NEGATIVE_CASES = [
    ("aws-access-key-id", AWS_ACCESS_KEY_SHORT),
    ("aws-secret-access-key", BARE_BASE64),
    ("google-api-key", GOOGLE_KEY_SHORT),
    ("github-token", GITHUB_TOKEN_SHORT),
    ("github-token", GITHUB_PAT_SHORT),
    ("slack-token", SLACK_TOKEN_MISS),
    ("stripe-key", STRIPE_KEY_SHORT),
    ("openai-api-key", OPENAI_KEY_SHORT),
    ("anthropic-api-key", ANTHROPIC_KEY_SHORT),
    ("discord-bot-token", DISCORD_TOKEN_MISS),
    ("telegram-bot-token", TELEGRAM_TOKEN_MISS),
    ("npm-token", NPM_TOKEN_SHORT),
    ("gitlab-token", GITLAB_TOKEN_SHORT),
    ("huggingface-token", HF_TOKEN_SHORT),
    ("sendgrid-key", SENDGRID_KEY_MISS),
    ("twilio-account-sid", TWILIO_SID_MISS),
    ("jwt", JWT_TWO_PARTS),
    ("pem-private-key", PEM_KEY_MISS),
    ("connection-string", CONNECTION_STRING_MISS),
    ("generic-assignment", PASSWORD_ASSIGNMENT_SHORT),
    ("generic-assignment", PASSWORD_ASSIGNMENT_UNQUOTED),
]


def _string(text: str, va: int | str | None = "0x402000") -> dict[str, Any]:
    entry: dict[str, Any] = {"text": text, "size": len(text), "kind": "ascii"}
    if va is not None:
        entry["va"] = va
    return entry


def _names(result: dict[str, Any]) -> set[str]:
    return {finding["name"] for finding in result["findings"]}


def _finding(result: dict[str, Any], name: str) -> dict[str, Any]:
    return next(finding for finding in result["findings"] if finding["name"] == name)


class TestPatternTable:
    def test_names_are_unique(self) -> None:
        names = [secret.name for secret in SECRET_PATTERNS]
        assert len(names) == len(set(names))

    def test_every_confidence_is_known(self) -> None:
        for secret in SECRET_PATTERNS:
            assert secret.confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)

    @pytest.mark.parametrize(("name", "sample", "value"), POSITIVE_CASES)
    def test_positive_sample_matches(self, name: str, sample: str, value: str) -> None:
        result = secrets.scan_secrets([_string(sample)])
        finding = _finding(result, name)
        assert finding["kind"] == "pattern"
        assert finding["value"] == value

    @pytest.mark.parametrize(("name", "value"), NEGATIVE_CASES)
    def test_near_miss_is_not_that_pattern(self, name: str, value: str) -> None:
        result = secrets.scan_secrets([_string(value)])
        assert name not in _names(result)

    def test_quoted_literal_needs_the_minimum_length(self) -> None:
        shorter = 'password = "' + "a" * (MIN_LITERAL_LENGTH - 1) + '"'
        assert "generic-assignment" not in _names(secrets.scan_secrets([_string(shorter)]))
        exact = 'password = "' + "a" * MIN_LITERAL_LENGTH + '"'
        assert "generic-assignment" in _names(secrets.scan_secrets([_string(exact)]))


class TestEntropy:
    def test_empty_value_has_no_entropy(self) -> None:
        assert secrets.entropy("") == 0.0

    def test_a_single_repeated_character_has_no_entropy(self) -> None:
        assert secrets.entropy("aaaa") == 0.0

    def test_two_equally_likely_characters_are_one_bit(self) -> None:
        assert secrets.entropy("ab") == pytest.approx(1.0)
        assert secrets.entropy("aabb") == pytest.approx(1.0)

    def test_base64_blob_is_high_entropy(self) -> None:
        assert secrets.looks_high_entropy(BASE64_BLOB) is True

    def test_hex_blob_is_high_entropy(self) -> None:
        assert secrets.looks_high_entropy(HEX_BLOB) is True

    def test_english_sentence_is_not(self) -> None:
        assert secrets.looks_high_entropy(ENGLISH_SENTENCE) is False

    def test_dotted_version_string_is_not(self) -> None:
        assert secrets.looks_high_entropy(DOTTED_VERSION) is False

    def test_long_lowercase_dictionary_word_is_not(self) -> None:
        assert secrets.looks_high_entropy(DICTIONARY_WORD) is False

    def test_lowercase_letters_only_never_qualify(self) -> None:
        assert secrets.looks_high_entropy("abcdefghijklmnopqrstuvwxyzabcdefghij") is False

    def test_digits_only_never_qualify(self) -> None:
        assert secrets.looks_high_entropy("12345678901234567890123456789012") is False

    def test_mixed_class_qualifies(self) -> None:
        assert secrets.looks_high_entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") is True

    def test_value_shorter_than_the_minimum_is_rejected(self) -> None:
        candidate = "aB3dE9fG2hJ5kL8"
        assert len(candidate) < MIN_ENTROPY_LENGTH
        assert secrets.looks_high_entropy(candidate) is False
        assert secrets.looks_high_entropy(candidate, min_length=8) is True

    def test_short_hex_blob_is_rejected(self) -> None:
        assert secrets.looks_high_entropy("4d5e6f7a8b9c0d1e") is False

    def test_hex_floor_is_below_the_general_floor(self) -> None:
        assert HEX_MIN_ENTROPY_BITS < MIN_ENTROPY_BITS

    def test_thresholds_are_honored(self) -> None:
        assert secrets.looks_high_entropy(BASE64_BLOB, min_entropy=6.0) is False

    def test_entropy_finding_names_the_shape(self) -> None:
        result = secrets.scan_secrets([_string(BASE64_BLOB)])
        finding = _finding(result, secrets.ENTROPY_NAME)
        assert finding["kind"] == "entropy"
        assert finding["confidence"] == CONFIDENCE_MEDIUM
        assert finding["value"] == BASE64_BLOB


class TestStagedPayload:
    def test_a_large_base64_run_is_a_payload_not_entropy(self) -> None:
        blob = "aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW6xY9zA2bC5dE7fG8==" * 100
        assert len(blob) >= MIN_PAYLOAD_LENGTH
        assert secrets.looks_staged_payload(blob) is True
        result = secrets.scan_secrets([_string(blob)])
        finding = _finding(result, secrets.PAYLOAD_NAME)
        assert finding["kind"] == "embedded-payload"
        assert finding["confidence"] == CONFIDENCE_MEDIUM
        assert "high-entropy" not in {entry["name"] for entry in result["findings"]}

    def test_a_key_sized_blob_is_not_a_payload(self) -> None:
        assert secrets.looks_staged_payload(BASE64_BLOB) is False

    def test_whitespace_disqualifies(self) -> None:
        blob = ("aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW6xY9zA2bC5dE7fG8==" * 100)[:4090] + " dead beef"
        assert secrets.looks_staged_payload(blob) is False

    def test_non_base64_bytes_disqualify(self) -> None:
        assert secrets.looks_staged_payload("!" * MIN_PAYLOAD_LENGTH) is False


class TestScan:
    def test_empty_input_yields_an_exact_empty_result(self) -> None:
        assert secrets.scan_secrets([]) == {
            "findings": [],
            "count": 0,
            "by_confidence": {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 0},
        }

    def test_entry_without_text_is_skipped(self) -> None:
        assert secrets.scan_secrets([{"va": "0x1000", "size": 0}])["count"] == 0

    def test_duplicate_value_keeps_the_highest_confidence_and_first_va(self) -> None:
        result = secrets.scan_secrets(
            [_string(AWS_SECRET, va="0x1000"), _string(AWS_SECRET_ASSIGNMENT, va="0x2000")]
        )
        merged = [finding for finding in result["findings"] if finding["value"] == AWS_SECRET]
        assert len(merged) == 1
        assert merged[0]["name"] == "aws-secret-access-key"
        assert merged[0]["confidence"] == CONFIDENCE_HIGH
        assert merged[0]["va"] == 0x1000
        assert result["by_confidence"] == {CONFIDENCE_HIGH: 1, CONFIDENCE_MEDIUM: 1}

    def test_findings_sort_by_confidence_then_name(self) -> None:
        result = secrets.scan_secrets(
            [
                _string(PASSWORD_ASSIGNMENT),
                _string(GITHUB_TOKEN),
                _string(JWT),
                _string(BASE64_BLOB),
            ]
        )
        assert [finding["name"] for finding in result["findings"]] == [
            "github-token",
            "jwt",
            "generic-assignment",
            "high-entropy",
        ]

    def test_findings_with_equal_confidence_and_name_sort_by_va(self) -> None:
        result = secrets.scan_secrets(
            [
                _string('password = "secondvalue"', va="0x2000"),
                _string('password = "firstvalue"', va="0x1000"),
            ]
        )
        assert [finding["name"] for finding in result["findings"]] == [
            "generic-assignment",
            "generic-assignment",
        ]
        assert [finding["va"] for finding in result["findings"]] == [0x1000, 0x2000]

    def test_findings_are_capped_while_count_is_exact(self) -> None:
        blobs = [
            f"aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW6xY{index:04d}zA2bC5d=="
            for index in range(MAX_FINDINGS + 5)
        ]
        result = secrets.scan_secrets([_string(blob) for blob in blobs])
        assert result["count"] == MAX_FINDINGS + 5
        assert len(result["findings"]) == MAX_FINDINGS
        assert result["by_confidence"][CONFIDENCE_MEDIUM] == MAX_FINDINGS + 5

    def test_by_confidence_counts_the_deduplicated_set(self) -> None:
        result = secrets.scan_secrets(
            [_string(GITHUB_TOKEN), _string(JWT), _string(PASSWORD_ASSIGNMENT)]
        )
        assert result["by_confidence"] == {CONFIDENCE_HIGH: 2, CONFIDENCE_MEDIUM: 1}

    def test_redaction_masks_the_middle_and_keeps_the_ends(self) -> None:
        redacted = secrets.redact(AWS_ACCESS_KEY)
        assert len(redacted) == len(AWS_ACCESS_KEY)
        assert redacted.startswith(AWS_ACCESS_KEY[:4])
        assert redacted.endswith(AWS_ACCESS_KEY[-4:])
        assert set(redacted[4:-4]) == {"*"}

    def test_redaction_of_a_short_value_is_whole(self) -> None:
        assert secrets.redact("abc") == "***"
        assert secrets.redact("abcdefgh") == "********"

    def test_va_is_reported_from_an_int_and_a_hex_string(self) -> None:
        result = secrets.scan_secrets(
            [_string(GITHUB_TOKEN, va=0x401000), _string(JWT, va="0x402000")]
        )
        by_name = {finding["name"]: finding for finding in result["findings"]}
        assert by_name["github-token"]["va"] == 0x401000
        assert by_name["jwt"]["va"] == 0x402000

    def test_missing_va_is_none(self) -> None:
        result = secrets.scan_secrets([_string(GITHUB_TOKEN, va=None)])
        assert result["findings"][0]["va"] is None

    def test_scan_caps_the_strings_it_reads(self) -> None:
        many = [
            _string(BASE64_BLOB, va=0x1000 + index) for index in range(MAX_STRINGS_INSPECTED + 5)
        ]
        result = secrets.scan_secrets(many)
        assert result["count"] == 1


class _StubEngine:
    """Engine surface with a fixed strings payload and a call log."""

    def __init__(
        self,
        *,
        strings: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._strings = strings if strings is not None else {"strings": []}
        self._error = error

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        if self._error is not None:
            raise self._error
        return self._strings


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(
        conn,
        sha256="5e" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
    )


class TestRunSecrets:
    def test_injected_strings_skip_the_engine_and_store_the_round_trip(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("must not be called"))
        result = secrets.run_secrets(
            conn,
            binary_id=binary_id,
            engine=stub,
            strings=[_string(GITHUB_TOKEN)],
        )
        assert result["binary_id"] == binary_id
        assert result["count"] == 1
        assert result["findings"][0]["name"] == "github-token"
        assert result["scanned"] == 1
        assert stub.calls == []
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECRETS) == result

    def test_engine_strings_are_used_when_none_are_injected(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(strings={"strings": [_string(JWT, va="0x402000")]})
        result = secrets.run_secrets(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["strings"]
        assert result["findings"][0]["name"] == "jwt"
        assert result["scanned"] == 1

    def test_empty_findings_are_stored(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        result = secrets.run_secrets(conn, binary_id=binary_id, engine=_StubEngine(), strings=[])
        assert result["findings"] == []
        assert result["count"] == 0
        assert result["scanned"] == 0
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECRETS) == result

    def test_scanned_counts_the_strings_examined(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        many = [
            _string(BASE64_BLOB, va=0x1000 + index) for index in range(MAX_STRINGS_INSPECTED + 5)
        ]
        result = secrets.run_secrets(conn, binary_id=binary_id, strings=many)
        assert result["scanned"] == MAX_STRINGS_INSPECTED

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            secrets.run_secrets(conn, binary_id=4242, strings=[])

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            secrets.run_secrets(conn, binary_id=binary_id, strings=[])

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            secrets.run_secrets(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            secrets.run_secrets(conn, binary_id=binary_id, engine=stub)

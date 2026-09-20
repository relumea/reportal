"""Tests for the error-code catalogue, its documentation and the `doc_url` field.

What the coverage check here can and cannot see: it reads every literal
`error=`/`code=` argument in the package plus the per-module error tables it
imports, so a new literal code fails the test until it is catalogued.  A code
built entirely from an exception's own vocabulary that no table lists would not
be caught; every such vocabulary is in the tables below.
"""

from __future__ import annotations

import ast
import json
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import json_body, wsgi_request

from reportal import api, engines, error_docs, matching, remote_ingest, store

SRC = Path(__file__).resolve().parents[1] / "src" / "reportal"
DOC = Path(__file__).resolve().parents[1] / error_docs.DOC_PATH

# Codes the API answers from an exception's own vocabulary rather than a
# literal at the call site.
EXCEPTION_TABLES: frozenset[str] = frozenset(
    {code for _kind, _status, code in api._DATA_TYPE_ERRORS}
    | {code for _kind, _status, code in api._SIGNATURE_ERRORS}
    | {code for _status, code in matching.TRANSFER_FAILURE_RESPONSE.values()}
    | {
        remote_ingest.ERROR_DISABLED,
        remote_ingest.ERROR_INVALID_URL,
        remote_ingest.ERROR_BLOCKED_TARGET,
        remote_ingest.ERROR_UNRESOLVABLE,
        remote_ingest.ERROR_UNSUPPORTED_CONTENT_TYPE,
        remote_ingest.ERROR_FETCH_FAILED,
        remote_ingest.ERROR_TOO_MANY_REDIRECTS,
        remote_ingest.ERROR_TOO_LARGE,
    }
)


def _literal_codes() -> set[str]:
    """Every literal `error=`/`code=` argument in the package's sources."""
    codes: set[str] = set()
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg in {"error", "code"} and isinstance(keyword.value, ast.Constant):
                    codes.add(str(keyword.value.value))
    return codes


def _url(code: str) -> str:
    """The URL *code* maps to, asserting it has an entry."""
    url = error_docs.doc_url(code)
    assert url is not None
    return url


def _documented_anchors() -> set[str]:
    """The code-section anchors `docs/ERRORS.md` publishes.

    The page's `##` headings are the index and the family headings; every
    documented code is a `###` section, so the extraction is unambiguous.
    """
    anchors: set[str] = set()
    for line in DOC.read_text().splitlines():
        if not line.startswith("### "):
            continue
        anchors.add(error_docs.heading_anchor(line[4:]))
    return anchors


class TestCatalogue:
    def test_every_literal_code_is_catalogued(self) -> None:
        missing = {
            code
            for code in _literal_codes() - EXCEPTION_TABLES
            if error_docs.doc_anchor(code) is None
        }
        assert missing == set()

    def test_every_exception_vocabulary_code_is_catalogued(self) -> None:
        missing = {code for code in EXCEPTION_TABLES if error_docs.doc_anchor(code) is None}
        assert missing == set()

    def test_the_catalogue_values_are_anchors_not_urls(self) -> None:
        assert all(
            anchor == error_docs.heading_anchor(anchor)
            for anchor in error_docs.ERROR_DOC_ANCHORS.values()
        )

    def test_the_documented_anchors_match_the_doc_headings(self) -> None:
        assert error_docs.documented_anchors() == _documented_anchors()

    def test_every_code_gets_a_live_url_or_none(self) -> None:
        assert error_docs.doc_url("no-scan") == f"{error_docs.DOC_BASE_URL}#no-scan"
        assert _url("binary not found").endswith("#binary-not-found")
        assert _url("last-analysis").endswith("#last-analysis")
        assert error_docs.doc_url("some-code-nobody-documented") is None

    @pytest.mark.parametrize(
        "code",
        [
            "narrative must be a boolean",
            "limit must be an integer",
            "scope_id must be an integer",
            "name must be a string",
            "top must be positive",
            "port must be between 0 and 65535",
            "invalid third_party_field",
            "invalid params",
        ],
    )
    def test_a_callsite_message_shares_the_invalid_params_section(self, code: str) -> None:
        assert error_docs.doc_anchor(code) == error_docs.INVALID_PARAMS_ANCHOR

    @pytest.mark.parametrize(
        ("code", "anchor"),
        [
            ("invalid kind", "invalid-kind"),
            ("invalid-kind", "invalid-kind"),
            ("invalid body", "invalid-body"),
            ("invalid-body", "invalid-body"),
            ("data type not found", "data-type-not-found"),
            ("data-type-not-found", "data-type-not-found"),
            ("signature not found", "signature-not-found"),
            ("signature-not-found", "signature-not-found"),
        ],
    )
    def test_two_spellings_of_one_code_share_an_anchor(self, code: str, anchor: str) -> None:
        assert error_docs.doc_anchor(code) == anchor


class TestErrorEnvelope:
    """A representative error from every status family carries a `doc_url`."""

    @pytest.fixture()
    def binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path=str(target))

    def _error(self, status: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        payload = cast(dict[str, Any], json_body(body, headers))
        assert error_docs.doc_url(str(payload["error"])) == payload["doc_url"]
        assert _url(str(payload["error"])).startswith(error_docs.DOC_BASE_URL)
        return payload

    def test_400_carries_its_doc_url(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400")
        payload = self._error(status, headers, body)
        assert payload["error"] == "invalid JSON body"
        assert payload["doc_url"] == f"{error_docs.DOC_BASE_URL}#invalid-json-body"

    def test_404_carries_its_doc_url(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999")
        assert status.startswith("404")
        payload = self._error(status, headers, body)
        assert payload["error"] == "binary not found"
        assert payload["doc_url"].endswith("#binary-not-found")

    def test_404_no_scan_carries_its_doc_url(
        self, conn: sqlite3.Connection, binary: int, fake_engine: Any
    ) -> None:
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary}/threat")
        assert status.startswith("404")
        payload = self._error(status, headers, body)
        assert payload["error"] == "no-scan"
        assert payload["doc_url"].endswith("#no-scan")

    def test_409_carries_its_doc_url(
        self, conn: sqlite3.Connection, binary: int, tmp_path: Path
    ) -> None:
        store.add_data_type(
            conn,
            binary_id=binary,
            name="PlayerInfo",
            kind="struct",
            size=4,
            members=[{"name": "field_0", "type": "int", "offset": 0, "size": 4}],
            source="manual",
        )
        target = tmp_path / "types.h"
        target.write_text("original", encoding="utf-8")
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary}/data-types/export",
            body=json.dumps({"path": str(target)}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("409")
        payload = self._error(status, headers, body)
        assert payload["error"] == "export-exists"
        assert payload["doc_url"].endswith("#export-exists")

    def test_413_carries_its_doc_url(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 4)
        body = (
            b"--boundary\r\n"
            b'Content-Disposition: form-data; name="file"; filename="big.exe"\r\n'
            b"\r\n"
            b"0123456789\r\n"
            b"--boundary--\r\n"
        )
        status, headers, raw = wsgi_request(
            "POST",
            "/api/binaries",
            body=body,
            headers={"Content-Type": "multipart/form-data; boundary=boundary"},
        )
        assert status.startswith("413")
        payload = self._error(status, headers, raw)
        assert payload["error"] == "file-too-large"
        assert payload["doc_url"].endswith("#file-too-large")

    def test_500_carries_its_doc_url(
        self, conn: sqlite3.Connection, binary: int, fake_engine: Any, monkeypatch: Any
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew analyze exited with code 1")

        monkeypatch.setattr(fake_engine, "analyze", boom)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary}/triage")
        assert status.startswith("500")
        payload = self._error(status, headers, body)
        assert payload["error"] == "engine-error"
        assert payload["doc_url"].endswith("#engine-error")

    def test_503_carries_its_doc_url(self, conn: sqlite3.Connection, binary: int) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary}/threat")
        assert status.startswith("503")
        payload = self._error(status, headers, body)
        assert payload["error"] == "engine-unavailable"
        assert payload["doc_url"].endswith("#engine-unavailable")

    def test_an_uncatalogued_code_answers_null_not_a_dead_link(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("reportal.error_docs.ERROR_DOC_ANCHORS", {})
        status, headers, body = wsgi_request("GET", "/api/binaries/999")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "binary not found"
        assert payload["doc_url"] is None

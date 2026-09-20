"""The error-code catalogue and the documentation URL every error body carries.

The hosted RevEng.AI API returns a ``doc_url`` beside every error, pointing at
the page that documents the code.  reportal does the same against its own
catalogue, :data:`docs/ERRORS.md` in this repository: :data:`ERROR_DOC_ANCHORS`
maps each code the API returns to that page's section anchor, and
:func:`doc_url` builds the absolute URL.

The catalogue and the page are checked against each other
(``tests/test_error_docs.py``): every code a route writes literally has an
entry, every anchor in the catalogue has exactly one heading in the page, and
every heading is an anchor the catalogue names.  A code with no entry gets no
``doc_url`` at all rather than a link to an anchor that does not exist, which is
what keeps the field honest.

A handful of the codes are built per field at the call site
(``f"{key} must be an integer"``, ``f"invalid {name}"``,
``f"{key} must be between {lo} and {hi}"``), so their exact text
depends on the request.  Those match :data:`PARAMETRIZED_DOC_ANCHORS` and share
the :data:`INVALID_PARAMS_ANCHOR` section, which documents the whole family.
"""

from __future__ import annotations

import re

# Where the catalogue is published.  The path is the section anchor's base and
# the one the checker reads; the repository URL is the package's own homepage.
DOC_PATH = "docs/ERRORS.md"
DOC_BASE_URL = "https://github.com/relumea/reportal/blob/main/docs/ERRORS.md"

# The section every field-level validation message shares.
INVALID_PARAMS_ANCHOR = "invalid-params"

# One anchor per code, in the page.  Two spellings of the same failure share an
# anchor (the page names both), so every entry links to a live section.
ERROR_DOC_ANCHORS: dict[str, str] = {
    "action not found": "action-not-found",
    "ambiguous-hash": "ambiguous-hash",
    "api-key-limit": "api-key-limit",
    "api-key-not-found": "api-key-not-found",
    "analysis not found": "analysis-not-found",
    "archive-too-large": "archive-too-large",
    "auto-busy": "auto-busy",
    "backend not found": "backend-not-found",
    "backend-unavailable": "backend-unavailable",
    "bad-password": "bad-password",
    "billing-error": "billing-error",
    "binary not found": "binary-not-found",
    "binary not on disk": "binary-not-on-disk",
    "blocked-target": "blocked-target",
    "candidate not found": "candidate-not-found",
    "candidate-has-no-name": "candidate-has-no-name",
    "candidate-has-no-signature": "candidate-has-no-signature",
    "collection not found": "collection-not-found",
    "comment not found": "comment-not-found",
    "component not found": "component-not-found",
    "component-missing": "component-missing",
    "conversation not found": "conversation-not-found",
    "corrupt-archive": "corrupt-archive",
    "data type not found": "data-type-not-found",
    "data-type-not-found": "data-type-not-found",
    "document not found": "document-not-found",
    "domain not found": "domain-not-found",
    "duplicate family": "duplicate-family",
    "forbidden": "forbidden",
    "secret forbidden": "forbidden",
    "duplicate member": "duplicate-member",
    "duplicate name": "duplicate-name",
    "duplicate parameter": "duplicate-parameter",
    "empty-file": "empty-file",
    "edge not found": "edge-not-found",
    "engine-error": "engine-error",
    "engine-unavailable": "engine-unavailable",
    "entry not found": "entry-not-found",
    "export-exists": "export-exists",
    "external-tool-required": "external-tool-required",
    "family not found": "family-not-found",
    "fetch-failed": "fetch-failed",
    "file-too-large": "file-too-large",
    "format-not-found": "format-not-found",
    "function not found": "function-not-found",
    "history not found": "history-not-found",
    "internal server error": "internal-server-error",
    "invalid JSON body": "invalid-json-body",
    "invalid body": "invalid-body",
    "invalid bulk request": "invalid-bulk-request",
    "invalid data type": "invalid-data-type",
    "invalid job": "invalid-job",
    "invalid job query": "invalid-job-query",
    "job not found": "job-not-found",
    "job-not-cancellable": "job-not-cancellable",
    "invalid kind": "invalid-kind",
    "invalid limit": "invalid-limit",
    "invalid password": "invalid-password",
    "invalid scope id": "invalid-scope-id",
    "invalid scope kind": "invalid-scope-kind",
    "invalid size range": "invalid-size-range",
    "invalid-labels": "invalid-labels",
    "invalid-region": "invalid-region",
    "invalid-team": "invalid-team",
    "invalid-user": "invalid-user",
    "invalid-api-key": "invalid-api-key",
    "invalid-body": "invalid-body",
    "invalid binary": "invalid-binary",
    "invalid-hash": "invalid-hash",
    "invalid feedback": "invalid-feedback",
    "invalid-kind": "invalid-kind",
    "invalid-limit": "invalid-limit",
    "invalid-url": "invalid-url",
    "journal-error": "journal-error",
    "last-analysis": "last-analysis",
    "llm-error": "llm-error",
    "llm-unavailable": "llm-unavailable",
    "mcp-unavailable": "mcp-unavailable",
    "member-not-found": "member-not-found",
    "model not found": "model-not-found",
    "no-artifact": "no-artifact",
    "no-decompilation": "no-decompilation",
    "no-doc": "no-doc",
    "no-docs": "no-docs",
    "no-engine-context": "no-engine-context",
    "no-file": "no-file",
    "no-flirt-scan": "no-flirt-scan",
    "no-graph": "no-graph",
    "no-line-comment": "no-line-comment",
    "manual-name": "manual-name",
    "no-pdf": "no-pdf",
    "no-proposal": "no-proposal",
    "no-report": "no-report",
    "no-run": "no-run",
    "no-scan": "no-scan",
    "no-signature-dir": "no-signature-dir",
    "no-symbols": "no-symbols",
    "no-pending-confirmation": "no-pending-confirmation",
    "no-strings": "no-strings",
    "no-such-match": "no-such-match",
    "secret not found": "secret-not-found",
    "no-labels": "no-labels",
    "no-packer": "no-packer",
    "no-unpacker": "no-unpacker",
    "no-workspace": "no-workspace",
    "unknown-packer": "unknown-packer",
    "unpack-failed": "unpack-failed",
    "node not found": "node-not-found",
    "not found": "not-found",
    "not-a-team-member": "not-a-team-member",
    "invite-not-found": "invite-not-found",
    "invite-used": "invite-used",
    "invite-expired": "invite-expired",
    "signup-disabled": "signup-disabled",
    "quota-exceeded": "quota-exceeded",
    "not-active": "not-active",
    "not-go": "not-go",
    "unreadable": "unreadable",
    "not-reloadable": "not-reloadable",
    "not-withdrawable": "not-withdrawable",
    "password-required": "password-required",
    "pipeline-unavailable": "pipeline-unavailable",
    "project not found": "project-not-found",
    "provide a component name or all": "provide-a-component-name-or-all",
    "provide a name or all, not both": "provide-a-name-or-all-not-both",
    "query-unsupported": "query-unsupported",
    "rate-limited": "rate-limited",
    "remote-ingest-disabled": "remote-ingest-disabled",
    "region not found": "region-not-found",
    "request body must be a JSON object": "request-body-must-be-a-json-object",
    "run not found": "run-not-found",
    "run-not-cancellable": "run-not-cancellable",
    "unsafe name": "unsafe-name",
    "same binary": "same-binary",
    "sandbox-disabled": "sandbox-disabled",
    "sandbox-unavailable": "sandbox-unavailable",
    "invalid-sandbox": "invalid-sandbox",
    "scope-forbidden": "scope-forbidden",
    "short-hash": "short-hash",
    "signature not found": "signature-not-found",
    "signature-conflict": "signature-conflict",
    "signature-not-found": "signature-not-found",
    "similarity-unavailable": "similarity-unavailable",
    "symbols-unreadable": "symbols-unreadable",
    "string not found": "string-not-found",
    "tag not found": "tag-not-found",
    "tag not on binary": "tag-not-on-binary",
    "team-exists": "team-exists",
    "team-not-found": "team-not-found",
    "too many transfers": "too-many-transfers",
    "too-many-documents": "too-many-documents",
    "too-many-files": "too-many-files",
    "too-many-members": "too-many-members",
    "too-many-redirects": "too-many-redirects",
    "transfers must be a non-empty list": "transfers-must-be-a-non-empty-list",
    "ui-not-built": "ui-not-built",
    "unauthorized": "unauthorized",
    "unexpected Host header": "unexpected-host-header",
    "unknown binary": "unknown-binary",
    "unknown collection": "unknown-collection",
    "unknown token": "unknown-token",
    "user-exists": "user-exists",
    "user-not-found": "user-not-found",
    "unmapped address": "unmapped-address",
    "unresolvable-host": "unresolvable-host",
    "unsupported-content-type": "unsupported-content-type",
    "unsupported-format": "unsupported-format",
    "write-failed": "write-failed",
}

# Message shapes built at the call site.  The text names the field and the
# expected value, so the whole family shares one section rather than one
# anchor per field.
PARAMETRIZED_DOC_ANCHORS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"[a-z_]+ must be (?:a|an)"
            r" (?:string|number|integer|boolean|non-empty string|list of strings|list of integers)"
        ),
        INVALID_PARAMS_ANCHOR,
    ),
    (re.compile(r"[a-z_]+ must be positive"), INVALID_PARAMS_ANCHOR),
    (re.compile(r"[a-z_]+ must be between \d+ and \d+"), INVALID_PARAMS_ANCHOR),
    (re.compile(r"invalid [a-z_-]+"), INVALID_PARAMS_ANCHOR),
)


def doc_anchor(code: str) -> str | None:
    """The section anchor documenting *code*, or None when it has no entry."""
    anchor = ERROR_DOC_ANCHORS.get(code)
    if anchor is not None:
        return anchor
    for pattern, fallback in PARAMETRIZED_DOC_ANCHORS:
        if pattern.fullmatch(code):
            return fallback
    return None


def doc_url(code: str) -> str | None:
    """The documentation URL for *code*, or None when there is nothing to link.

    A code the catalogue does not name gets no URL: a link to a guessed anchor
    would be a dead link, and the caller learns more from an explicit null.
    """
    anchor = doc_anchor(code)
    return None if anchor is None else f"{DOC_BASE_URL}#{anchor}"


def heading_anchor(heading: str) -> str:
    """The GitHub heading anchor for *heading*, the rule the page is checked with."""
    return re.sub(r"[^a-z0-9 _-]", "", heading.strip().casefold()).replace(" ", "-")

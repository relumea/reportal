"""Deterministic PDF summary reports for reportal.

The pages are laid out here and written by reportlab's canvas: reportal decides
what goes on each page -- the sections, the tables, the row caps -- and the
library owns the file format, the objects, the page tree, the xref table and
the string escaping.  Output is written with ``invariant=1`` and no page
compression, so the same stored rows and the same date produce the same bytes
and a test can still read the expected strings straight out of the stream.

``render_report`` assembles the summary from the scans reportal already stored.
The single engine call it may make is the optional coverage summary: it runs
``engine.report`` only when the stored ``report`` scan is absent and the caller
supplied an engine, and a failed run is skipped with the section omitted like
any other missing scan.  Every section is left out when its scan is absent.

Text is measured with reportlab's Helvetica metrics rather than a mean glyph
advance, so a wrapped line and a table cell are exactly as wide as the viewer
will draw them.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas as pdfcanvas

from reportal import (
    attack_surface,
    behavior,
    decompiler_scripts,
    engines,
    exploitability,
    gobuildinfo,
    hardening,
    lineage,
    store,
)
from reportal._paths import reports_dir

# File name a generated PDF takes inside a binary's workspace report directory.
REPORT_PDF_NAME = "report.pdf"


# ── Page geometry (PDF points, US Letter) ──────────────────────────

PAGE_WIDTH = 612.0
PAGE_HEIGHT = 792.0
MARGIN_LEFT = 54.0
MARGIN_RIGHT = 54.0
MARGIN_TOP = 54.0
MARGIN_BOTTOM = 60.0

# Baselines of the running header and footer, both inside the margins.
HEADER_BASELINE_Y = PAGE_HEIGHT - 34.0
FOOTER_BASELINE_Y = 34.0

# ── Faces and sizes ────────────────────────────────────────────────

# The two base-14 faces, named as reportlab (and every PDF viewer) names them.
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
TITLE_FONT_SIZE = 18.0
HEADING_FONT_SIZE = 12.0
BODY_FONT_SIZE = 9.0
NOTE_FONT_SIZE = 8.0

HEADING_LINE_HEIGHT = 16.0
LINE_HEIGHT = 11.5
NOTE_LINE_HEIGHT = 10.0

HEADING_SPACE_BEFORE = 10.0
HEADING_SPACE_AFTER = 4.0
SPACER_HEIGHT = 6.0
RULE_SPACE = 7.0
BAND_HEIGHT = 1.5
CELL_VERTICAL_PAD = 3.0

# Rendering caps: a huge scan must not turn into a thousand-page report.
MAX_ROWS_PER_SECTION = 20
MAX_TECHNIQUE_ROWS = 20
MAX_IOC_ROWS = 12
MAX_LINEAGE_ROWS = 10
MAX_CELL_CHARS = 160
RULE_BODY_LINE_CAP = 24

# Coverage fields rendered in reading order.
SUMMARY_FIELDS: tuple[str, ...] = (
    "total_functions",
    "covered_functions",
    "coverage_pct",
    "matched_pct",
    "byte_coverage_pct",
)

# Fingerprint fields rendered in reading order.
FINGERPRINT_FIELDS: tuple[str, ...] = (
    "md5",
    "sha1",
    "sha256",
    "crc32",
    "format",
    "arch",
    "size",
    "imphash",
    "rich_header_hash",
)

# Dossier `meta` fields rendered in reading order.
TRIAGE_META_FIELDS: tuple[str, ...] = ("format", "image_base", "text_va", "text_size")

# Dossier count sections rendered in reading order.
TRIAGE_COUNT_SECTIONS: tuple[str, ...] = ("strings", "imports", "references", "functions")

# Page object marker; the negative lookahead keeps the page tree out of a count.
_PAGE_OBJECT = re.compile(rb"/Type /Page\b")

# One recorded drawing operation: ("text", x, y, size, bold, gray, text),
# ("line", y) or ("rect", y, height).
_Op = tuple[Any, ...]


# ── Text primitives ────────────────────────────────────────────────


def text_width(text: str, size: float, *, bold: bool = False) -> float:
    """Return the advance width of *text* in points, from the font metrics."""
    return float(pdfmetrics.stringWidth(text, FONT_BOLD if bold else FONT_REGULAR, size))


def _split_to_width(word: str, width: float, size: float, *, bold: bool) -> str:
    """The longest prefix of *word* that fits *width* (at least one character)."""
    end = 1
    for index in range(2, len(word) + 1):
        if text_width(word[:index], size, bold=bold) > width:
            break
        end = index
    return word[:end]


def wrap_text(
    text: str, width: float, size: float = BODY_FONT_SIZE, *, bold: bool = False
) -> list[str]:
    """Wrap *text* onto lines no wider than *width* points.

    A word wider than the line is hard-split so a long path or hash cannot
    overflow the frame.  An empty string yields one empty line, which keeps
    callers from special-casing a blank cell.
    """
    rendered = _text(text).strip()
    if not rendered:
        return [""]
    lines: list[str] = []
    current = ""
    for word in rendered.split():
        candidate = f"{current} {word}".strip()
        if text_width(candidate, size, bold=bold) <= width:
            current = candidate
            continue
        if current:
            lines.append(current)
            current = ""
        while text_width(word, size, bold=bold) > width:
            piece = _split_to_width(word, width, size, bold=bold)
            lines.append(piece)
            word = word[len(piece) :]
        current = word
    if current or not lines:
        lines.append(current)
    return lines


def _text(value: Any) -> str:
    """Render *value* as display text; None is empty and a bool is yes/no."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _truncate(value: Any, limit: int = MAX_CELL_CHARS) -> str:
    """Render *value* as display text, shortened past *limit* characters."""
    rendered = _text(value)
    return rendered if len(rendered) <= limit else rendered[: max(0, limit - 3)] + "..."


def _entry(value: Any) -> dict[str, Any]:
    """Return *value* when it is an object, else an empty object."""
    return value if isinstance(value, dict) else {}


def _entries(value: Any) -> list[Any]:
    """Return *value* when it is a list, else an empty list."""
    return value if isinstance(value, list) else []


def _rows(value: Any) -> list[dict[str, Any]]:
    """Return the object entries of a list, dropping anything else."""
    return [item for item in _entries(value) if isinstance(item, dict)]


# ── Layout ─────────────────────────────────────────────────────────


class PdfLayout:
    """Reusable text layout that paginates when the cursor passes the bottom margin.

    ``text``, ``heading`` and ``table`` append to the current page; a call that
    would cross :data:`MARGIN_BOTTOM` opens a new page first.  Nothing is drawn
    until :meth:`build`, which replays the recorded operations onto a reportlab
    canvas and adds the running header and the ``Page N of M`` footer, so the
    footer can name the total the layout only knows once it is complete.
    """

    def __init__(self, *, header: str) -> None:
        self._header = header
        self._pages: list[list[_Op]] = []
        self._ops: list[_Op] = []
        self._sections: list[str] = []
        self._closed = False
        self._y = PAGE_HEIGHT - MARGIN_TOP

    @property
    def content_width(self) -> float:
        """Width of the text frame in points."""
        return PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT

    @property
    def sections(self) -> tuple[str, ...]:
        """Headings rendered so far, in document order."""
        return tuple(self._sections)

    @property
    def page_count(self) -> int:
        """Pages started so far, including the open one while it is still open."""
        return len(self._pages) if self._closed else len(self._pages) + 1

    def _new_page(self) -> None:
        self._pages.append(self._ops)
        self._ops = []
        self._y = PAGE_HEIGHT - MARGIN_TOP

    def _fit(self, height: float) -> None:
        if self._y - height < MARGIN_BOTTOM:
            self._new_page()

    def _draw(self, text: str, x: float, y: float, size: float, *, bold: bool, gray: bool) -> None:
        self._ops.append(("text", x, y, size, bold, gray, text))

    def spacer(self, height: float = SPACER_HEIGHT) -> None:
        """Advance the cursor by *height* points, breaking the page when needed."""
        self._fit(height)
        self._y -= height

    def rule(self) -> None:
        """Draw a horizontal separator across the frame."""
        self._fit(RULE_SPACE)
        self._ops.append(("line", self._y - 2.0))
        self._y -= RULE_SPACE

    def band(self, height: float = BAND_HEIGHT) -> None:
        """Draw a filled rectangle across the frame, used as a title separator."""
        self._fit(height)
        self._ops.append(("rect", self._y - height, height))
        self._y -= height

    def text(
        self,
        value: Any,
        *,
        size: float = BODY_FONT_SIZE,
        bold: bool = False,
        indent: float = 0.0,
        gray: bool = False,
    ) -> None:
        """Write *value* as wrapped body text at the cursor."""
        line_height = NOTE_LINE_HEIGHT if gray else LINE_HEIGHT
        for line in wrap_text(_text(value), self.content_width - indent, size, bold=bold):
            self._fit(line_height)
            self._draw(line, MARGIN_LEFT + indent, self._y, size, bold=bold, gray=gray)
            self._y -= line_height

    def note(self, value: Any) -> None:
        """Write *value* as small gray text."""
        self.text(value, size=NOTE_FONT_SIZE, gray=True)

    def heading(self, title: str) -> None:
        """Write a section heading and record it in :attr:`sections`."""
        self._sections.append(title)
        self._y -= HEADING_SPACE_BEFORE
        self._fit(HEADING_LINE_HEIGHT + HEADING_SPACE_AFTER)
        self._draw(title, MARGIN_LEFT, self._y, HEADING_FONT_SIZE, bold=True, gray=False)
        self._y -= HEADING_LINE_HEIGHT + HEADING_SPACE_AFTER

    def table(self, headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
        """Write a table whose columns take the given fractions of the frame."""
        columns = [self.content_width * fraction for fraction in widths]
        self._table_row(headers, columns, bold=True)
        self.rule()
        for row in rows:
            self._table_row(row, columns, bold=False)

    def _table_row(self, cells: list[Any], columns: list[float], *, bold: bool) -> None:
        wrapped = [
            wrap_text(_truncate(cell), max(1.0, column - 2.0 * CELL_VERTICAL_PAD), BODY_FONT_SIZE)
            for cell, column in zip(cells, columns, strict=False)
        ]
        height = max(len(lines) for lines in wrapped) * LINE_HEIGHT + CELL_VERTICAL_PAD
        self._fit(height)
        top = self._y
        x = MARGIN_LEFT
        for lines, column in zip(wrapped, columns, strict=False):
            y = top
            for line in lines:
                self._draw(line, x + CELL_VERTICAL_PAD, y, BODY_FONT_SIZE, bold=bold, gray=False)
                y -= LINE_HEIGHT
            x += column
        self._y = top - height

    def key_values(self, rows: list[tuple[str, str]]) -> None:
        """Write field/value rows as a two-column table."""
        self.table(["field", "value"], [[field, value] for field, value in rows], [0.32, 0.68])

    def build(self) -> bytes:
        """Close the open page and serialize every page with reportlab."""
        self._pages.append(self._ops)
        self._ops = []
        self._closed = True
        total = len(self._pages)
        buffer = io.BytesIO()
        pdf = pdfcanvas.Canvas(
            buffer,
            pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
            invariant=1,
            pageCompression=0,
            pdfVersion=(1, 4),
        )
        for index, ops in enumerate(self._pages, start=1):
            pdf.setFillGray(0.0)
            pdf.setFont(FONT_BOLD, BODY_FONT_SIZE)
            pdf.drawString(MARGIN_LEFT, HEADER_BASELINE_Y, self._header)
            pdf.setFont(FONT_REGULAR, NOTE_FONT_SIZE)
            pdf.drawCentredString(PAGE_WIDTH / 2.0, FOOTER_BASELINE_Y, f"Page {index} of {total}")
            for op in ops:
                self._paint(pdf, op)
            pdf.showPage()
        pdf.save()
        return buffer.getvalue()

    @staticmethod
    def _paint(pdf: Any, op: _Op) -> None:
        """Draw one recorded operation on the canvas."""
        kind = op[0]
        if kind == "text":
            _, x, y, size, bold, gray, text = op
            pdf.setFillGray(0.45 if gray else 0.0)
            pdf.setFont(FONT_BOLD if bold else FONT_REGULAR, size)
            pdf.drawString(x, y, text)
            pdf.setFillGray(0.0)
        elif kind == "line":
            pdf.setStrokeGray(0.65)
            pdf.setLineWidth(0.6)
            pdf.line(MARGIN_LEFT, op[1], PAGE_WIDTH - MARGIN_RIGHT, op[1])
            pdf.setStrokeGray(0.0)
        else:
            pdf.setFillGray(0.2)
            pdf.rect(MARGIN_LEFT, op[1], PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT, op[2], stroke=0)
            pdf.setFillGray(0.0)


def page_count(data: bytes) -> int:
    """Return the number of page objects in *data*.

    Counts the ``/Type /Page`` markers the writer emits, so it is exact for a
    reportal-generated document and cheap enough for a status call.
    """
    return len(_PAGE_OBJECT.findall(data))


# ── Section assembly ───────────────────────────────────────────────


def _scan(conn: sqlite3.Connection, binary_id: int, kind: str) -> dict[str, Any] | None:
    """Return the binary's newest stored scan of *kind*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    stored = store.get_scan(conn, analysis_id, kind)
    return stored if isinstance(stored, dict) else None


def _count_rows(counts: dict[str, Any]) -> list[list[Any]]:
    return [[str(key), _text(value)] for key, value in counts.items()]


def _title_block(layout: PdfLayout, binary: dict[str, Any], generated: str) -> None:
    layout.text(_text(binary.get("name")) or "binary", size=TITLE_FONT_SIZE, bold=True)
    rows = [
        ("sha256", _text(binary.get("sha256"))),
        ("format", _text(binary.get("format"))),
        ("arch", _text(binary.get("arch"))),
        ("size", _text(binary.get("size"))),
    ]
    if generated:
        rows.append(("generated", generated))
    layout.key_values(rows)
    layout.spacer(BAND_HEIGHT)
    layout.band()


def _coverage_section(
    layout: PdfLayout,
    conn: sqlite3.Connection,
    binary_id: int,
    engine: Any,
) -> None:
    summary: dict[str, Any] = {}
    stored = _scan(conn, binary_id, store.SCAN_KIND_REPORT)
    if stored is not None:
        summary = _entry(stored.get("summary"))
    if not summary and engine is not None and engine.available():
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is not None:
            try:
                result = engine.report(project_dir, reports_dir(binary_id))
            except engines.EngineError:
                result = None
            if isinstance(result, dict):
                summary = _entry(result.get("summary"))
    if not summary:
        return
    layout.heading("Coverage")
    layout.key_values(
        [(field, _text(summary.get(field))) for field in SUMMARY_FIELDS if field in summary]
    )
    status_counts = _entry(summary.get("status_counts"))
    if status_counts:
        layout.table(["status", "count"], _count_rows(status_counts), [0.5, 0.5])


def _fingerprint_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    fingerprint = store.get_fingerprint(conn, binary_id)
    if not fingerprint:
        return
    layout.heading("Fingerprint")
    layout.key_values(
        [
            (field, _text(fingerprint.get(field)))
            for field in FINGERPRINT_FIELDS
            if fingerprint.get(field) not in (None, "")
        ]
    )


def _capabilities_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_CAPABILITIES)
    if not scan:
        return
    entries = _rows(scan.get("capabilities"))
    if not entries:
        return
    layout.heading("Capabilities")
    layout.key_values([("count", _text(scan.get("count")))])
    layout.table(
        ["capability", "confidence", "evidence"],
        [
            [entry.get("name"), entry.get("confidence"), entry.get("evidence_count")]
            for entry in entries[:MAX_ROWS_PER_SECTION]
        ],
        [0.55, 0.2, 0.25],
    )


def _triage_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_TRIAGE)
    if not scan:
        return
    toolchain = _entry(scan.get("toolchain"))
    meta = _entry(scan.get("meta"))
    rows: list[tuple[str, str]] = []
    if toolchain:
        rows.append(
            (
                "toolchain",
                " ".join(
                    filter(
                        None, (_text(toolchain.get("family")), _text(toolchain.get("version_hint")))
                    )
                ),
            )
        )
        if toolchain.get("confidence") not in (None, ""):
            rows.append(("confidence", _text(toolchain.get("confidence"))))
    rows.extend((field, _text(meta.get(field))) for field in TRIAGE_META_FIELDS if field in meta)
    if not rows and not any(section in scan for section in TRIAGE_COUNT_SECTIONS):
        return
    layout.heading("Triage")
    if rows:
        layout.key_values(rows)
    counts = [
        [section, _entry(scan.get(section)).get("count")]
        for section in TRIAGE_COUNT_SECTIONS
        if _entry(scan.get(section))
    ]
    if counts:
        layout.table(["section", "count"], counts, [0.5, 0.5])


def _function_triage_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_FUNCTION_TRIAGE)
    if not scan:
        return
    entries = _rows(scan.get("functions"))
    if not entries:
        return
    layout.heading("Function triage")
    layout.key_values(
        [
            ("model", _text(scan.get("model"))),
            ("count", _text(scan.get("count"))),
        ]
    )
    layout.table(
        ["score", "name", "va", "method", "summary"],
        [
            [
                entry.get("score"),
                entry.get("name"),
                hex(int(entry["va"]))
                if isinstance(entry.get("va"), int)
                else _text(entry.get("va")),
                entry.get("method"),
                _truncate(entry.get("summary")),
            ]
            for entry in entries[:MAX_ROWS_PER_SECTION]
        ],
        [0.08, 0.22, 0.12, 0.13, 0.45],
    )


def _security_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_SECURITY)
    if not scan:
        return
    layout.heading("Security")
    layout.key_values([("findings", _text(scan.get("count")))])
    by_severity = _entry(scan.get("by_severity"))
    if by_severity:
        layout.table(["severity", "count"], _count_rows(by_severity), [0.5, 0.5])


def _crypto_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_CRYPTO)
    if not scan:
        return
    layout.heading("Crypto")
    layout.key_values([("findings", _text(scan.get("count")))])
    by_confidence = _entry(scan.get("by_confidence"))
    if by_confidence:
        layout.table(["confidence", "count"], _count_rows(by_confidence), [0.5, 0.5])


def _threat_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_THREAT)
    if not scan:
        return
    layout.heading("Threat")
    ioc_counts = _entry(scan.get("ioc_counts"))
    if ioc_counts:
        layout.table(
            ["ioc category", "count"],
            _count_rows(ioc_counts)[:MAX_IOC_ROWS],
            [0.6, 0.4],
        )
    techniques = _rows(scan.get("techniques"))
    if techniques:
        layout.table(
            ["technique", "name", "confidence"],
            [
                [entry.get("id"), _truncate(entry.get("name"), 60), entry.get("confidence")]
                for entry in techniques[:MAX_TECHNIQUE_ROWS]
            ],
            [0.25, 0.55, 0.2],
        )


def _secrets_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_SECRETS)
    if not scan:
        return
    layout.heading("Secrets")
    layout.key_values(
        [
            ("findings", _text(scan.get("count"))),
            ("strings scanned", _text(scan.get("scanned"))),
        ]
    )
    by_confidence = _entry(scan.get("by_confidence"))
    if by_confidence:
        layout.table(["confidence", "count"], _count_rows(by_confidence), [0.5, 0.5])
    layout.note("Finding values are redacted; the stored scan holds them.")


def _behavior_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    stored = [
        (domain, _scan(conn, binary_id, kind))
        for domain, kind in behavior.DOMAIN_SCAN_KINDS.items()
    ]
    present = [(domain, scan) for domain, scan in stored if scan]
    if not present:
        return
    layout.heading("Behavior")
    rows: list[list[Any]] = []
    for domain, scan in present:
        by_confidence = _entry(scan.get("by_confidence"))
        rows.append(
            [
                domain,
                _text(scan.get("count")),
                _text(by_confidence.get(behavior.capabilities.CONFIDENCE_HIGH)),
                _text(by_confidence.get(behavior.capabilities.CONFIDENCE_MEDIUM)),
            ]
        )
    layout.table(["domain", "findings", "high", "medium"], rows, [0.4, 0.2, 0.2, 0.2])


def _protocols_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_PROTOCOLS)
    if not scan:
        return
    entries = _rows(scan.get("protocols"))
    if not entries:
        return
    layout.heading("Protocols")
    layout.key_values([("count", _text(scan.get("count")))])
    layout.table(
        ["protocol", "confidence", "ports"],
        [
            [
                entry.get("protocol"),
                entry.get("confidence"),
                ", ".join(str(port) for port in _entries(entry.get("ports"))),
            ]
            for entry in entries[:MAX_ROWS_PER_SECTION]
        ],
        [0.45, 0.2, 0.35],
    )


def _hardening_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    stored = [
        (domain, _scan(conn, binary_id, kind))
        for domain, kind in hardening.DOMAIN_SCAN_KINDS.items()
    ]
    present = [(domain, scan) for domain, scan in stored if scan]
    if not present:
        return
    layout.heading("Hardening")
    rows: list[list[Any]] = []
    for domain, scan in present:
        rows.append(
            [
                domain,
                _text(scan.get("count")),
                _text(scan.get("packer_likelihood")),
            ]
        )
    layout.table(["domain", "findings", "packer likelihood"], rows, [0.4, 0.25, 0.35])


def _remediation_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, store.SCAN_KIND_REMEDIATION)
    if not scan:
        return
    layout.heading("Remediation")
    layout.key_values(
        [
            ("rule", _text(scan.get("rule_name"))),
            ("specificity", _text(scan.get("specificity"))),
            ("strings", _text(scan.get("string_count"))),
            ("imports", _text(scan.get("import_count"))),
            ("validated", _text(scan.get("validated"))),
        ]
    )
    body = _text(scan.get("rule")).splitlines()
    if body:
        capped = body[:RULE_BODY_LINE_CAP]
        if len(body) > len(capped):
            capped.append(f"... {len(body) - len(capped)} more line(s)")
        for line in capped:
            layout.text(line, size=NOTE_FONT_SIZE, gray=True)


def _lineage_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    comparisons = lineage.stored_comparisons(conn, binary_id)
    if not comparisons:
        return
    layout.heading("Lineage")
    rows: list[list[Any]] = []
    for comparison in comparisons[:MAX_LINEAGE_ROWS]:
        summary = _entry(comparison.get("summary"))
        rows.append(
            [
                _truncate(comparison.get("right_name"), 40),
                summary.get(lineage.STATUS_UNCHANGED),
                summary.get(lineage.STATUS_CHANGED),
                summary.get(lineage.STATUS_ADDED),
                summary.get(lineage.STATUS_REMOVED),
                summary.get("matched_percent"),
            ]
        )
    layout.table(
        ["other", "unchanged", "changed", "added", "removed", "matched %"],
        rows,
        [0.3, 0.14, 0.14, 0.14, 0.14, 0.14],
    )


def _attack_surface_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    try:
        payload = attack_surface.attack_surface(conn, binary_id)
    except KeyError:
        return
    if not payload["available"]:
        return
    layout.heading("Attack surface")
    layout.key_values(
        [
            ("network", _text(payload["network"]["count"])),
            ("local input", _text(payload["local_input"]["count"])),
            ("crypto", _text(payload["crypto"]["count"])),
        ]
    )
    rows: list[list[Any]] = []
    for group in ("network", "local_input", "crypto"):
        for row in payload[group]["rows"][:MAX_ROWS_PER_SECTION]:
            rows.append([group, _truncate(row["name"], 48), _truncate(row["source"], 24)])
            if len(rows) >= MAX_ROWS_PER_SECTION:
                break
        if len(rows) >= MAX_ROWS_PER_SECTION:
            break
    if rows:
        layout.table(["group", "entry", "source"], rows, [0.25, 0.5, 0.25])


def _exploitability_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    try:
        payload = exploitability.rank(conn, binary_id)
    except KeyError:
        return
    if not payload["available"]:
        return
    layout.heading("Exploitability")
    layout.key_values(
        [
            ("findings", _text(payload["count"])),
            ("reachable", _text(payload["reachable"])),
            ("unreachable", _text(payload["unreachable"])),
        ]
    )
    rows = payload["rows"]
    if rows:
        layout.table(
            ["severity", "function", "reachability"],
            [
                [row.get("severity"), _truncate(row.get("function"), 40), row.get("reachability")]
                for row in rows[:MAX_ROWS_PER_SECTION]
            ],
            [0.25, 0.45, 0.3],
        )


def _gobuildinfo_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    scan = _scan(conn, binary_id, gobuildinfo.SCAN_KIND)
    if not scan:
        return
    layout.heading("Go build")
    layout.key_values(
        [
            ("version", _text(scan.get("version"))),
            ("module", _text(scan.get("module")) or "none"),
        ]
    )
    dependencies = scan.get("dependencies")
    rows = (
        [
            [entry.get("module"), entry.get("version")]
            for entry in dependencies[:MAX_ROWS_PER_SECTION]
            if isinstance(entry, dict)
        ]
        if isinstance(dependencies, list)
        else []
    )
    if rows:
        layout.table(["module", "version"], rows, [0.65, 0.35])


def _renames_section(layout: PdfLayout, conn: sqlite3.Connection, binary_id: int) -> None:
    try:
        payload = decompiler_scripts.collect(conn, binary_id)
    except decompiler_scripts.ScriptError:
        return
    if not payload["entries"]:
        return
    layout.heading("Renames")
    layout.key_values(
        [
            ("renames", _text(len(payload["entries"]))),
            ("functions", _text(payload["count"])),
        ]
    )
    rows = [
        [_truncate(hex(int(entry.get("va", 0))), 18), _truncate(str(entry.get("name")), 48)]
        for entry in payload["entries"][:MAX_ROWS_PER_SECTION]
        if isinstance(entry, dict)
    ]
    if rows:
        layout.table(["address", "name"], rows, [0.3, 0.7])


# ── Public entry points ────────────────────────────────────────────


@dataclass(frozen=True)
class RenderedReport:
    """A rendered PDF plus the section headings and page count it carries."""

    data: bytes
    sections: tuple[str, ...]
    pages: int


def _render(
    conn: sqlite3.Connection, *, binary_id: int, engine: Any, generated: str
) -> RenderedReport:
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    layout = PdfLayout(header=_text(binary.get("name")) or "binary")
    _title_block(layout, binary, generated)
    _coverage_section(layout, conn, binary_id, engine)
    _fingerprint_section(layout, conn, binary_id)
    _capabilities_section(layout, conn, binary_id)
    _triage_section(layout, conn, binary_id)
    _function_triage_section(layout, conn, binary_id)
    _security_section(layout, conn, binary_id)
    _crypto_section(layout, conn, binary_id)
    _threat_section(layout, conn, binary_id)
    _secrets_section(layout, conn, binary_id)
    _behavior_section(layout, conn, binary_id)
    _protocols_section(layout, conn, binary_id)
    _hardening_section(layout, conn, binary_id)
    _remediation_section(layout, conn, binary_id)
    _lineage_section(layout, conn, binary_id)
    _attack_surface_section(layout, conn, binary_id)
    _exploitability_section(layout, conn, binary_id)
    _gobuildinfo_section(layout, conn, binary_id)
    _renames_section(layout, conn, binary_id)
    data = layout.build()
    return RenderedReport(data=data, sections=layout.sections, pages=page_count(data))


def render_report(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: engines.RebrewEngine | None = None,
    generated: str = "",
) -> bytes:
    """Render a binary's PDF summary from its stored scans.

    *generated* is the only caller-supplied string and the only varying text in
    the document.  *engine* is used solely for the optional coverage summary:
    it runs ``engine.report`` when no ``report`` scan is stored, and a missing
    engine or a failed run leaves the section out.

    Raises :class:`KeyError` for an unknown binary id.
    """
    return _render(conn, binary_id=binary_id, engine=engine, generated=generated).data


def write_report(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    path: str | Path,
    engine: engines.RebrewEngine | None = None,
    generated: str = "",
) -> dict[str, Any]:
    """Render the PDF and write it atomically to *path*.

    Returns ``{"path", "bytes", "pages", "sections"}``.  Raises
    :class:`KeyError` for an unknown binary id.
    """
    report = _render(conn, binary_id=binary_id, engine=engine, generated=generated)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(report.data)
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(handle)
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return {
        "path": str(target),
        "bytes": len(report.data),
        "pages": report.pages,
        "sections": list(report.sections),
    }

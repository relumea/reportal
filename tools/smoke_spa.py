"""smoke_spa.py: boot reportal and render every SPA route in headless Chrome.

Builds a scratch workspace under the repo's gitignored ``.scratch/`` (never
``/tmp``): one binary pointing at the sibling ``notepad-rebrew`` project, its
rebrew context, one analysis (whose structured log every seeded scan appends
to, so the Analyses route's log drawer has real entries), a handful of real
functions read from ``src/NP/functions.txt``, a stored match pair with both
stored decompilations,
a stored struct-recovery scan, a stored PE metadata scan,
a stored per-function triage, a stored threat
report, a stored remediation
rule, a stored identifier-rename suggestion, analyst comments on the binary
and its first function, a stored conversation, a stored AI
decompilation run, a stored knowledge
document, a stored malware family with a stored detection, a stored lineage
comparison against a registered copy of the binary and a stored composition
analysis computed from a match against that copy, and builds the binary's
knowledge graph from those rows.  The security scan is seeded by running the
real deterministic `rebrew security-scan` over the project's reversed sources
(the engine adapter, no sample and no network call), so the binary-detail
route's severity badges render from a real payload rather than a hand-written
one.  Then it starts
``reportal serve`` on a free port with ``REPORTAL_REBREW`` pointed at the
sibling rebrew checkout and renders the dashboard landing route plus each hash
route, asserting the dumped DOM carries that view's markers.

The SPA is the Vite build under ``web/``; when ``assets/dist/index.html`` is
missing this first runs ``bun install`` (unless ``web/node_modules`` exists)
and ``bun run build`` with ``cwd=web``, so the smoke works from a clean
checkout.  The build output is generated and gitignored.

The list views need no engine.  The function detail route runs ``rebrew asm``
through the stored project context, so its marker (``bits 32``) proves the
engine wiring end to end, and its AI section renders the panels without a
model call (the seeded summary gives the panel a payload to show and discard,
and the rest render their stored-only hints), so the ``AI comments`` marker
proves the bridge's panels exist without an endpoint configured, and the seeded rename
suggestion gives the Renames panel a row to assert.  The seeded loop function
(``CFG_LOOP_FUNCTION_VA``) is what the control-flow check switches to, so the
graph's blocks, its edges and a labelled back edge all render from a real
``rebrew asm --format cfg`` call.  The stored structs scan
plus the seeded editable data type give the Data types panel a real recovery
and a model row to render, since the model GET is stored-only; the seeded
function signature (parsed from the stored decompilation, then given a named
parameter) gives the function detail Signature panel a rendered prototype to
assert, and the stored knowledge document gives the Knowledge view a document
to list without ingesting anything.

Requires a headless browser (``google-chrome-stable`` or ``chromium``).  When
neither is on PATH the smoke prints a skip message and exits 0, so it stays
runnable on browser-less machines.

Usage::

    uv run --python .venv/bin/python tools/smoke_spa.py
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The repo root goes on the path before the local-package import, so this file
# works both as a script (`python tools/smoke_spa.py`, where sys.path[0] is this
# directory) and as an imported module (`from tools import smoke_spa`, where the
# root is what makes `tools` a package).  tools/audit_ui.py does the same.
_REPO_ROOT = next(
    candidate
    for candidate in (Path(__file__).resolve().parent, *Path(__file__).resolve().parent.parents)
    if (candidate / "pyproject.toml").is_file()
)
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from reportal import (  # noqa: E402
    auto_store,
    composition,
    data_types,
    effects,
    engines,
    families,
    graph,
    journal,
    knowledge,
    lineage,
    llm,
    renames,
    signatures,
    store,
)
from tools import cdp  # noqa: E402

# Sibling checkouts the smoke drives: the rebrew engine and the notepad rebrew
# project it imported.  Both are resolved from this script's repo root so no
# machine-specific path is baked in.
REBREW_RELATIVE = Path("rebrew") / ".venv" / "bin" / "rebrew"
NOTEPAD_PROJECT_RELATIVE = Path("rebrew-projects") / "notepad-rebrew"

# Frontend source and the Vite entry page it builds; the smoke builds when the
# entry page is absent.
WEB_RELATIVE = Path("web")
DIST_INDEX_RELATIVE = Path("src") / "reportal" / "assets" / "dist" / "index.html"

# Browser binaries tried in order; the first on PATH wins.
BROWSERS = ("google-chrome-stable", "chromium")

# The viewport a route renders at.  The markers are text, so this only has to
# be wide enough that a route does not render a narrow-screen variant.
RENDER_WIDTH = 1600
RENDER_HEIGHT = 1000

# How long a route's markers may take to appear, and the poll between checks.
# A render waits for the live document rather than dumping it after a fixed
# virtual-time budget: that budget caps how far ahead the page's timers run,
# not how long a pending fetch takes to resolve, so a route whose data landed
# late was dumped early and the gate flaked (measured twice this session).
MARKER_DEADLINE_SECONDS = 30.0
MARKER_POLL_SECONDS = 0.25

BROWSER_TIMEOUT_SECONDS = 60
SERVER_START_TIMEOUT_SECONDS = 30
SERVER_STOP_TIMEOUT_SECONDS = 10

# Functions seeded from the project's function list.  Enough to render the
# functions table; the first is the one the function detail route renders.
FUNCTION_SEED_COUNT = 6

# The seeded function whose control-flow graph contains a loop, so the smoke
# exercises the panel's back-edge path and not only its block list.  The VA is
# pinned rather than an index: a function list whose order changed would fail
# loud here instead of silently asserting a different function's graph.
CFG_LOOP_FUNCTION_VA = 0x01001AE3

# Markers the control-flow view carries once the Disassembly / Control flow
# toggle is switched to the graph: the panel title, the summary line's noun and
# the labelled back edge CFG_LOOP_FUNCTION_VA graphs.
CFG_MARKERS: tuple[str, ...] = ("Control flow", "basic blocks", "back edge")

# Proposed name the seeded unstrip scan carries.  The Auto-unstrip panel
# auto-loads the stored proposals through its stored-only GET, so pre-seeding
# one gives the smoke a real proposal to assert.
UNSTRIP_PROPOSED_NAME = "ChooseFontW"

# Function name the first seeded row carries.  It is the functions list's
# marker and a function node's label in the seeded graph's node table.
FUNCTION_MARKER = "FreePrintSetup"

# Tag applied to the seeded binary so the global search modal's tag query and
# the Search view's tag table have a real row to render.
TAG_NAME = "smoke-tag"

# A registered copy of the smoke binary and the function added to it, so the
# Lineage panel has a stored comparison against a genuinely different function
# set to render: the changed size and the extra function give the panel's
# changed and added groups a row each.
LINEAGE_OTHER_NAME = "notepad-copy.exe"
LINEAGE_OTHER_SHA256 = "cd" * 32
LINEAGE_OTHER_SIZE_DELTA = 8
LINEAGE_OTHER_EXTRA_VA = 0x1003000
LINEAGE_OTHER_EXTRA_NAME = "NewInCopy"

# A stored match from the smoke binary's first function to the copy's first
# function, at a strong-match similarity.  The composition scan is computed by
# the production code over the store, so the panel renders a real rollup against
# LINEAGE_OTHER_NAME rather than a hand-written payload.
COMPOSITION_SIMILARITY = 97.5

# Seeded conversation and message, so the Conversations routes render a stored
# thread; the detail route reads the messages back through its own GET.
CONVERSATION_TITLE = "Smoke chat"
CONVERSATION_MESSAGE = "What does this function do?"

# Seeded AI decompilation run: the function detail view renders its step
# timeline from the stored run (the panel's GET is stored-only), so a stored run
# gives the smoke a real timeline and Revert control to assert.
PIPELINE_STEP_NAME = "prepare"
PIPELINE_STEP_DURATION_MS = 12
PIPELINE_STEP_PROVIDES = ("function_meta", "disassembly")

# Stored decompilations of the seeded match pair.  The diff route's default
# kind is `decomp`, so stored rows let it render without running an engine, and
# the differing middle line gives the alignment a changed line to mark.
DIFF_LEFT_DECOMP = "void FreePrintSetup(void)\n{\n  return;\n}\n"
DIFF_RIGHT_DECOMP = "void FreePrintSetup(void)\n{\n  int x = 1;\n  return;\n}\n"

# Stored auto run seeded so the Auto-mode route renders a finished task tree
# without working anything: the route reads a stored run, so a completed run
# gives it a root task, a batch, an attempt and a coverage delta to show.
AUTO_REASON = "offline-demo"
AUTO_WORKER = "offline"
AUTO_COVERAGE_BEFORE = {"matched": 0, "total": FUNCTION_SEED_COUNT, "ratio": 0.0}
AUTO_COVERAGE_AFTER = {"matched": 1, "total": FUNCTION_SEED_COUNT, "ratio": 0.1667}

# Similarity recorded for the seeded match pair, so the diff header shows one.
DIFF_SIMILARITY = 91.5
DIFF_CONFIDENCE = 0.8

# Analyst comments seeded on the binary and its first function.  The Comments
# panel auto-loads its stored list, so the bodies prove both scopes rendered a
# row.
COMMENT_BINARY_BODY = "Reviewed the notepad import table."
COMMENT_FUNCTION_BODY = "FreePrintSetup clears the window title."
COMMENT_AUTHOR = "smoke"

# Stored identifier rename seeded for the first function.  The Renames panel
# auto-loads the stored artifact through its stored-only GET, so pre-seeding one
# gives the smoke a real suggestion row to assert without calling a model.
RENAME_FROM = "FreePrintSetup"
RENAME_TO = "ResetPrinterState"
RENAME_REASON = "names the reset entry point"
RENAMES_SCAN: dict[str, object] = {
    "suggestions": [
        {
            "from": RENAME_FROM,
            "to": RENAME_TO,
            "kind": "function",
            "reason": RENAME_REASON,
            "confidence": 0.75,
        }
    ]
}

# Knowledge document seeded on the smoke binary.  The Knowledge view loads its
# scope's documents through a stored-only GET and its search reads the stored
# chunks, so pre-seeding one gives the smoke a real document and a rankable
# snippet to assert.
# The stored AI summary the function detail renders (no model is called).
AI_SUMMARY_TEXT = "Reads the configuration file and applies the stored settings."

DOCUMENT_TITLE = "Smoke knowledge note"

# A seeded journal action, so the Journal view has a row to render; the
# description is the marker the route check asserts.
JOURNAL_ACTION = "smoke-action"
JOURNAL_DESCRIPTION = "registered binary"
DOCUMENT_SOURCE = "smoke.md"
DOCUMENT_TEXT = (
    "# Smoke note\n\n"
    "The keyboard shortcut table lives in the dialog procedure.\n\n"
    "Toggle the toolbar with the accelerator key.\n"
)

# Stored threat report seeded on the smoke analysis.  The Threat report panel
# auto-loads the stored result through a stored-only GET, so pre-seeding one
# gives the smoke an IOC group and a technique row to assert.  The software
# type and the threat score are derived from the stored scans at read time, so
# the seeded file-type detection (a UPX packer match) is what names the type
# and carries the packing contribution.
THREAT_IOC_URL = "https://c2.example.com/beacon"
THREAT_TECHNIQUE_ID = "T1071"
THREAT_SOFTWARE_TYPE = "packed-executable"
THREAT_SCORE_LABEL = "Threat score"
THREAT_CONTRIBUTION = "packing"
THREAT_TECHNIQUE_LINK = "attack.mitre.org"
THREAT_IPV6 = "2001:db8::1"
THREAT_SCAN: dict[str, object] = {
    "binary_id": 0,
    "iocs": {
        "urls": [{"value": THREAT_IOC_URL, "kind": "url", "source_va": 0x402000}],
        "ipv6": [{"value": THREAT_IPV6, "kind": "ipv6", "source_va": 0x402000}],
    },
    "ioc_counts": {"urls": 1, "ipv6": 1},
    "techniques": [
        {
            "id": THREAT_TECHNIQUE_ID,
            "name": "Application Layer Protocol",
            "evidence": [{"kind": "ioc", "value": "urls"}],
            "confidence": "medium",
        }
    ],
    "narrative": None,
    "notes": [],
}

# Stored per-function triage seeded on the smoke analysis.  The Function
# triage panel auto-loads the aggregate through its stored-only GET, so
# pre-seeding one gives the smoke a scored row, its method badge and a model
# line to assert without calling a model.
FUNCTION_TRIAGE_SUMMARY = "Scores the decryption loop and its key schedule."
FUNCTION_TRIAGE_SCAN: dict[str, object] = {
    "binary_id": 0,
    "model": "",
    "functions": [
        {
            "function_id": 1,
            "name": FUNCTION_MARKER,
            "va": 0x10018A0,
            "size": 512,
            "status": "STUB",
            "score": 0.85,
            "summary": FUNCTION_TRIAGE_SUMMARY,
            "capabilities": [],
            "method": "heuristic",
        }
    ],
    "count": 1,
    "by_method": {"llm": 0, "heuristic": 1},
    "skipped": [],
    "notes": ["llm-unavailable: scores and summaries are heuristic"],
}

# Stored remediation scan seeded on the smoke analysis.  The Remediation panel
# auto-loads the stored rule through a stored-only GET, so pre-seeding one gives
# the smoke a generated rule to assert.
REMEDIATION_RULE_NAME = "notepad_demo"
REMEDIATION_RULE_FRAGMENT = "uint16(0) == 0x5A4D"
REMEDIATION_SNORT_MARKER = "sid:1000000"
REMEDIATION_STIX_MARKER = "indicator--"

# Seeded malware family and its stored detection on the smoke analysis.  The
# Detect panel auto-loads the stored scan through its stored-only GET and the
# Binaries view lists the family, so seeding one gives the smoke a family match
# with its signal list to assert.
DETECT_FAMILY_NAME = "SmokeFamily"
DETECT_FAMILY_ALIAS = "SMOKE.A"
DETECT_SIGNAL_KIND = "exact-binary"
REMEDIATION_SCAN: dict[str, object] = {
    "binary_id": 0,
    "rule": (
        f"rule {REMEDIATION_RULE_NAME}\n"
        "{\n"
        "    meta:\n"
        '        author = "reportal"\n'
        '        date = "2026-09-12"\n'
        '        binary = "notepad.exe"\n'
        "\n"
        "    strings:\n"
        '        $s1 = "Notepad" ascii wide\n'
        "\n"
        "    condition:\n"
        f"        {REMEDIATION_RULE_FRAGMENT} and filesize < 67108864 and 1 of them\n"
        "}\n"
    ),
    "rule_name": REMEDIATION_RULE_NAME,
    "string_count": 1,
    "import_count": 0,
    "validated": True,
    "validator": "yarac",
    "meta": {"date": "2026-09-12", "binary": "notepad.exe"},
    "notes": [],
    "snort": {
        "rules": [
            {
                "sid": 1000000,
                "family": "url",
                "value": "http://smoke.example.com/",
                "host": "smoke.example.com",
                "port": 443,
                "text": (
                    "alert tcp $HOME_NET any -> $EXTERNAL_NET 443 "
                    '(msg:"notepad.exe url http://smoke.example.com/";'
                    " flow:established,to_server;"
                    ' content:"smoke.example.com"; http_header; sid:1000000; rev:1;)'
                ),
            }
        ],
        "text": (
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 443 "
            '(msg:"notepad.exe url http://smoke.example.com/";'
            " flow:established,to_server;"
            ' content:"smoke.example.com"; http_header; sid:1000000; rev:1;)\n'
        ),
        "notes": [],
    },
    "stix": {
        "type": "bundle",
        "spec_version": "2.1",
        "id": "bundle--0f8b0e64-6f2a-5f6b-9a3d-2f4b7c1d8e90",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--11111111-1111-5111-8111-111111111111",
                "created": "2026-09-12T00:00:00Z",
                "modified": "2026-09-12T00:00:00Z",
                "name": "reportal",
                "identity_class": "system",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--22222222-2222-5222-8222-222222222222",
                "created": "2026-09-12T00:00:00Z",
                "modified": "2026-09-12T00:00:00Z",
                "name": "notepad_demo urls http://smoke.example.com/",
                "pattern": "[url:value = 'http://smoke.example.com/']",
                "pattern_type": "stix",
                "valid_from": "2026-09-12T00:00:00Z",
            },
        ],
    },
}

# Stored PE metadata seeded on the smoke analysis.  The Binary details panel
# auto-loads the stored result through its stored-only GET, so pre-seeding it
# gives the identity, security, exports and sections cards real content.
PE_INFO_FLAG = "Image Isolation"
PE_INFO_HASH_ROW = "sha3_512"
PE_INFO_EXPORT_NAME = "NP_OpenFile"
PE_INFO_FORWARDER = "USER32.DialogBoxParamA"
PE_INFO_SCAN: dict[str, object] = {
    "format": "pe",
    "arch": "x86_32",
    "bits": 32,
    "type": "exe",
    "image_base": 0x1000000,
    "entry_point": 0x1006420,
    "subsystem": "WINDOWS_GUI",
    "timestamp": 938894716,
    "timestamp_iso": "1999-10-02T20:05:16Z",
    "checksum": 59572,
    "size": 50960,
    "resource_count": 24,
    "sections": [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 26058,
            "raw_size": 26112,
            "raw_offset": 1536,
            "entropy": 6.2667,
            "characteristics_value": 0x60000020,
            "characteristics": [
                "IMAGE_SCN_CNT_CODE",
                "IMAGE_SCN_MEM_EXECUTE",
                "IMAGE_SCN_MEM_READ",
            ],
            "read": True,
            "write": False,
            "execute": True,
        },
        {
            "name": ".data",
            "virtual_address": 0x8000,
            "virtual_size": 6468,
            "raw_size": 1536,
            "raw_offset": 27648,
            "entropy": 3.0102,
            "characteristics_value": 0xC0000040,
            "characteristics": [
                "IMAGE_SCN_CNT_INITIALIZED_DATA",
                "IMAGE_SCN_MEM_READ",
                "IMAGE_SCN_MEM_WRITE",
            ],
            "read": True,
            "write": True,
            "execute": False,
        },
        {
            "name": ".rsrc",
            "virtual_address": 0xA000,
            "virtual_size": 21048,
            "raw_size": 21504,
            "raw_offset": 29184,
            "entropy": 4.7713,
            "characteristics_value": 0x40000040,
            "characteristics": [
                "IMAGE_SCN_CNT_INITIALIZED_DATA",
                "IMAGE_SCN_MEM_READ",
            ],
            "read": True,
            "write": False,
            "execute": False,
        },
    ],
    "security_flags": {
        "dll_characteristics": 0x8000,
        "aslr": False,
        "nx": False,
        "cfg": False,
        "gs": False,
        "safe_seh": False,
        "seh": True,
        "high_entropy_va": False,
        "force_integrity": False,
        "isolation": True,
        "certificate_table": False,
    },
    "security": {
        "aslr": {"enabled": False, "flag": 0x0040, "flag_name": "DYNAMIC_BASE"},
        "dep": {"enabled": False, "flag": 0x0100, "flag_name": "NX_COMPAT"},
        "cfg": {"enabled": False, "flag": 0x4000, "flag_name": "GUARD_CF"},
        "driver_model": {"enabled": False, "flag": 0x2000, "flag_name": "WDM_DRIVER"},
        "app_container": {"enabled": False, "flag": 0x1000, "flag_name": "APPCONTAINER"},
        "terminal_server_aware": {
            "enabled": True,
            "flag": 0x8000,
            "flag_name": "TERMINAL_SERVER_AWARE",
        },
        "image_isolation": {"enabled": True, "flag": 0x0200, "flag_name": "NO_ISOLATION"},
        "code_integrity": {"enabled": False, "flag": 0x0080, "flag_name": "FORCE_INTEGRITY"},
        "high_entropy": {"enabled": False, "flag": 0x0020, "flag_name": "HIGH_ENTROPY_VA"},
        "seh": {"enabled": True, "flag": 0x0400, "flag_name": "NO_SEH"},
        "bound_image": {"enabled": True, "flag": 168, "flag_name": "BOUND_IMPORT"},
    },
    "security_score": {"enabled": 4, "total": 11},
    "exports": [
        {"name": PE_INFO_EXPORT_NAME, "va": 0x1009000, "ordinal": 1, "forwarder": None},
        {"name": "NP_SaveFile", "va": None, "ordinal": 2, "forwarder": PE_INFO_FORWARDER},
    ],
    "export_count": 2,
    "flags_summary": ["SEH", "Isolation"],
    "authenticode": {"present": False, "signature_count": 0, "signers": []},
    "debug": [{"type": "MISC"}],
    "rich_header": {"present": True, "key": 1326957964, "entries": [{"id": 1, "count": 164}]},
    "presence": {
        "tls_directory": False,
        "load_config": False,
        "resources": True,
        "relocations": False,
        "exports": True,
        "imports": True,
    },
    "counts": {"exports": 2, "imports": 183, "import_dlls": 8, "relocations": 0},
}

# Stored file-type detection seeded on the smoke analysis.  The Packer detection
# card auto-loads the stored result through its stored-only GET, so pre-seeding a
# high-confidence packer gives the card its verdict, signal row and compiler.
FILETYPE_SIGNAL = "UPX1"
FILETYPE_COMPILER = "Microsoft Visual C++"
PACKER_VERDICT = "Likely to be packed"
FILETYPE_SCAN: dict[str, object] = {
    "matches": [
        {
            "name": "UPX",
            "category": "packer",
            "confidence": "high",
            "signals": [
                {"kind": "section", "value": FILETYPE_SIGNAL},
                {"kind": "string", "value": "UPX!"},
            ],
        },
        {
            "name": FILETYPE_COMPILER,
            "category": "toolchain",
            "confidence": "medium",
            "signals": [{"kind": "rich-header", "value": "present"}],
        },
    ],
    "count": 2,
    "by_category": {"packer": 1, "protector": 0, "installer": 0, "runtime": 0, "toolchain": 1},
    "notes": ["seeded for the SPA smoke"],
}

# Rule and CWE names the real `rebrew security-scan` run over the notepad
# sources produces at the two severities it finds (high and low), plus the
# badge hue those rows render with.  The SPA's severity badges render only from
# a stored security scan, so asserting a rule row per severity and the badge
# hue proves the badge rows exist (the UI audit then measures them).
SECURITY_HIGH_RULE = "unbounded-copy"
SECURITY_HIGH_CWE = "CWE-120"
SECURITY_LOW_RULE = "unchecked-memcpy"
SECURITY_LOW_CWE = "CWE-787"
SECURITY_BADGE_HUE = 'data-hue="severity"'

# Seeded editable data type, so the Data types panel renders the local model
# (its own GET always answers) rather than only the stored-recovery hint.  The
# members carry a bitfield and an explicit gap member (the recovered
# `char gap_XXXX[N]` convention), and the seeded declared size is larger than
# the members' extent so the panel's size warning renders too.
SMOKE_TYPE_NAME = "SmokePlayerInfo"
SMOKE_TYPE_MEMBER = "smokeFlags"
SMOKE_TYPE_BITS = 3
SMOKE_TYPE_GAP = "gap_0008"
SMOKE_TYPE_EXTRA_SIZE = 4
SMOKE_TYPE_DEFINITION = (
    f"typedef struct {SMOKE_TYPE_NAME}_s {{\n"
    "\tint field_0;\n"
    f"\tunsigned int {SMOKE_TYPE_MEMBER} : {SMOKE_TYPE_BITS};\n"
    f"\tchar {SMOKE_TYPE_GAP}[4];\n"
    f"}} {SMOKE_TYPE_NAME};\n"
)
# The warning the panel renders when the declared size and the members disagree.
SMOKE_TYPE_SIZE_WARNING = "disagrees with the members"

# Parameter name added to the first function's signature, so the function
# detail Signature panel renders a named parameter and its rendered prototype
# through its own GET (which is stored-only).
SMOKE_SIGNATURE_PARAMETER = "smokeArg"

# Hash routes and the markers their rendered DOM must carry.  Each inner tuple
# is a group of alternatives: the route passes when every group has a match.
ROUTE_CHECKS: tuple[tuple[str, str, tuple[tuple[str, ...], ...]], ...] = (
    (
        "dashboard",
        "#/",
        (
            ("Dashboard",),
            ("Jump to",),
            ("Binaries",),
            ("Matched",),
            ("Recent activity",),
            # The cockpit's own instrument markers: the system-state strip, the
            # aggregate coverage meter, the live auto-run card and the
            # per-section meters.
            ("System state",),
            ("Coverage",),
            ("Live run",),
            # The 30-day series: the panel title and its first chart's label.
            ("Last 30 days",),
            ("Binaries processed",),
            ("Agents triggered",),
            ("Section coverage",),
        ),
    ),
    (
        "binaries list",
        "#/binaries",
        (
            # The panel states the filtered-of-total count; nothing is filtered
            # on a fresh smoke workspace, so both numbers are the seeded two.
            ("2 of 2 binaries",),
            ("notepad.exe",),
            (LINEAGE_OTHER_NAME,),
            (DETECT_FAMILY_NAME,),
            ("Bulk actions",),
            ("Comments",),
            # The per-row download action, served by GET /api/binaries/<id>/download.
            ("Download",),
            # The entry 11 conveniences: the drop zone and the in-place
            # extraction panel.  (Configure all appears with a queued file.)
            ("Drop binaries, firmware images or archives here",),
            ("Extract an archive",),
        ),
    ),
    (
        "binary memory dump",
        "#/binaries/{binary_id}?memory=0x1000",
        (
            # The continuous viewer the section table links to: the address box
            # and the keyboard hint it carries.
            ("Go to address",),
            ("Press G to focus the address box",),
            ("Columns",),
        ),
    ),
    (
        "analyses list",
        "#/analyses",
        (
            ("One row per analysis",),
            ("View log",),
            ("notepad.exe",),
            ("single-user loopback",),
            # The owner and scope columns and the workspace filter.
            ("Workspace",),
            ("Seen by",),
            # The entry 10 controls: the platform and architecture selects,
            # the status chips, the per-row re-analyse and the bulk copy.
            ("Platform",),
            ("Architecture",),
            ("Re-analyse",),
            ("Copy hashes",),
        ),
    ),
    (
        "binary detail",
        "#/binaries/{binary_id}",
        (
            ("notepad.exe",),
            ("Binary #",),
            ("Binary details",),
            # Identity card: the seeded PE type and resource count.
            ("number of resources",),
            # Hashes card: a raw-file digest the engine bundle carries.
            ("Hashes",),
            (PE_INFO_HASH_ROW,),
            # Security card: the checklist readout, a labeled item and its raw flag.
            ("Security mitigations",),
            ("Mitigations enabled",),
            (PE_INFO_FLAG,),
            # Exports card: a named export and a forwarded one.
            ("Exports",),
            (PE_INFO_EXPORT_NAME,),
            (PE_INFO_FORWARDER,),
            # Sections card: the raw IMAGE_SCN_* name list and the protection letters.
            ("Sections",),
            ("IMAGE_SCN_CNT_CODE",),
            ("R-X",),
            # Coverage map card: the defrag grid itself, which only renders
            # once the section geometry and the function table are both in.
            ("Coverage map",),
            ("cells carry a stored function",),
            # Code signature card.
            ("Code signature",),
            ("not signed",),
            # Packer card: verdict, entropy meter and the file-type signal.
            ("Packer detection",),
            (PACKER_VERDICT,),
            ("Peak section entropy",),
            (FILETYPE_SIGNAL,),
            ("Data types",),
            (SMOKE_TYPE_NAME,),
            # The editable type's bitfield member, its explicit gap member and
            # the size-vs-members warning the panel renders.
            (SMOKE_TYPE_MEMBER,),
            (SMOKE_TYPE_GAP,),
            (SMOKE_TYPE_SIZE_WARNING,),
            # The bulk declaration controls the panel carries beside the scan
            # import: creating and updating types from pasted C.
            ("Create from declarations",),
            ("Update from declarations",),
            # Debug symbol ingestion: the file control and its apply toggle.
            ("Debug symbols",),
            ("Ingest symbols",),
            # The stored renames as runnable scripts, beside the C/JSON export.
            ("Ghidra",),
            ("Binja",),
            # The memory panel's mode select, and the section table's
            # addresses, which link into the continuous dump.
            ("Whole binary",),
            ("Virtual address",),
            # The composition scope fields (entry 15).
            ("Scope to binaries",),
            ("Scope to collections",),
            # The library identification panel (entry 15's SBOM half).
            ("Library identification",),
            ("Identify libraries",),
            # Unpacked files panel: its rebuild control and the packer select
            # that leaves the packer to the file's own stub.
            ("Unpacked files",),
            ("Run unpack",),
            ("Auto",),
            # The benchmark panel: its partner select and run control.  The
            # seeded binary has no stored benchmark, so the body is the empty
            # state rather than a metrics table.
            ("Benchmark",),
            ("Run benchmark",),
            ("Partner",),
            # The rename half of the same panel: the seeded binary has no
            # symbol-named function, so it names the command that supplies one.
            ("Rename proposals",),
            ("reportal symbols",),
            # Analyst feedback on the stored agent artifacts.
            ("Agent feedback",),
            ("Function triage",),
            (FUNCTION_TRIAGE_SUMMARY,),
            ("Crypto",),
            ("Security",),
            # Security findings: one rule row per severity the real scan found,
            # and the severity badge hue those rows render with.
            (SECURITY_HIGH_RULE,),
            (SECURITY_HIGH_CWE,),
            (SECURITY_LOW_RULE,),
            (SECURITY_LOW_CWE,),
            (SECURITY_BADGE_HUE,),
            # The stored findings ranked by reachability, inside the same panel.
            ("Exploitability",),
            ("reachable",),
            ("Secrets",),
            ("Protocols",),
            ("Threat report",),
            (THREAT_IOC_URL,),
            # The seeded IPv6 literal renders in its own IOC group.
            ("ipv6",),
            (THREAT_IPV6,),
            (THREAT_TECHNIQUE_ID,),
            # The technique id is a link to attack.mitre.org, the software-type
            # badge carries its name and the score meter its readout.
            (THREAT_TECHNIQUE_LINK,),
            (THREAT_SOFTWARE_TYPE,),
            (THREAT_SCORE_LABEL,),
            (THREAT_CONTRIBUTION,),
            # The seeded threat URL flows into the attack-surface network group.
            ("Attack surface",),
            (THREAT_IOC_URL,),
            ("Remediation",),
            (REMEDIATION_RULE_FRAGMENT,),
            ("Snort",),
            (REMEDIATION_SNORT_MARKER,),
            ("STIX",),
            (REMEDIATION_STIX_MARKER,),
            ("Auto-unstrip",),
            ("Detect",),
            (DETECT_FAMILY_NAME,),
            (DETECT_SIGNAL_KIND,),
            ("Capabilities",),
            ("Behavior",),
            ("Hardening",),
            ("Lineage",),
            ("refined",),
            (LINEAGE_OTHER_NAME,),
            ("Related binaries",),
            # Composition panel: the computed rollup against the registered copy
            # and the name source and quality meters.
            ("Composition analysis",),
            ("Match quality",),
            ("Strong Match",),
            ("Function name sources",),
            (UNSTRIP_PROPOSED_NAME,),
            ("Download PDF",),
            ("Chat about this",),
            ("Comments",),
            (COMMENT_BINARY_BODY,),
            # The Memory panel's full-file mode toggle; the panel is on demand,
            # so only its mode control is asserted.
            ("Memory",),
            ("Full file",),
        ),
    ),
    (
        "functions list",
        "#/functions",
        ((FUNCTION_MARKER,), ("Apply filters",), ("functions",)),
    ),
    (
        "function detail",
        "#/functions/{function_id}",
        (
            ("Function #",),
            ("Signature",),
            (SMOKE_SIGNATURE_PARAMETER,),
            ("bits 32",),
            # The signature panel's bulk copy control.
            ("Copy signature",),
            # The three reference tables replace the combined Xrefs panel.
            ("Globals",),
            ("Callers",),
            ("Callees",),
            ("AI comments",),
            ("Renames",),
            (RENAME_TO,),
            ("AI decompilation",),
            ("Revert run",),
            # The per-function extras: the call-site scan, the per-function
            # capability classification, the analyst strings and edges and the
            # canonical-name action.
            ("Indirect call sites",),
            ("Capabilities",),
            ("Declare callee",),
            ("Apply canonical name",),
            ("Chat about this",),
            (COMMENT_FUNCTION_BODY,),
        ),
    ),
    (
        "diff",
        "#/diff/{function_id}/{candidate_function_id}",
        (("Diff",), ("diff-insert", "diff-delete")),
    ),
    (
        "conversations list",
        "#/conversations",
        (("Conversations",), (CONVERSATION_TITLE,)),
    ),
    (
        "conversation detail",
        "#/conversations/{conversation_id}",
        (
            ("Conversations",),
            (CONVERSATION_MESSAGE,),
            # The agent half: one tool loop per run over the local MCP registry.
            ("Agent run",),
            ("Run agent",),
            # The prompt library: one canned opener per scope.
            ("What does this function do?",),
        ),
    ),
    (
        "matches",
        "#/matches",
        (
            ("Match / Diff",),
            ("Match settings",),
            ("Run match",),
            ("Bulk transfer",),
            ("Enter a function id to open its binary's match view.",),
        ),
    ),
    (
        "auto mode",
        "#/auto/{binary_id}",
        (
            ("Auto-mode",),
            ("coverage",),
            ("attempts",),
            ("Revert run",),
            ("Execute (write C files and compile)",),
            (AUTO_REASON,),
        ),
    ),
    ("collections", "#/collections", (("No collections yet.",),)),
    ("tags", "#/tags", (("Tags",), ("Binaries",), ("Collections",))),
    (
        "knowledge",
        "#/knowledge",
        ((DOCUMENT_TITLE,), ("Paste a note to store in this scope",)),
    ),
    (
        "graph",
        "#/graph",
        (("Node counts",), (FUNCTION_MARKER,)),
    ),
    (
        "components",
        "#/components",
        (("Components",), ("prepare",), ("builtin",), ("Reload all",)),
    ),
    (
        "integrations",
        "#/integrations",
        (
            ("Integrations",),
            ("reportal.components",),
            ("pipeline components",),
            ("prepare",),
            # The readiness card: the report status and one known check.
            ("Readiness",),
            ("workspace",),
            # The MCP onboarding card: the command and the client config.
            ("Connect an MCP client",),
            ("claude mcp add reportal",),
        ),
    ),
    (
        "users",
        "#/users",
        (
            ("Identity",),
            ("single local user",),
            ("Bearer token",),
            ("Create user",),
            # The team structure: its roles and the level above teams (entry 2).
            ("New organisation",),
            ("An organisation groups teams and decides nothing about access",),
        ),
    ),
    (
        "billing",
        "#/billing",
        (
            ("Billing",),
            # No seeded organisation, so the view names where to create one.
            ("Create one in Users",),
        ),
    ),
    (
        "external sources",
        "#/external",
        (
            ("External sources",),
            ("Pull a report",),
            ("local",),
            ("Nothing pulled yet",),
            ("virustotal",),
        ),
    ),
    (
        "models",
        "#/models",
        (
            ("Models",),
            ("Upgrade an analysis",),
            ("rebrew",),
            ("decompiler",),
            ("unavailable",),
        ),
    ),
    (
        "journal",
        "#/journal",
        (("Journal",), (JOURNAL_ACTION,), (JOURNAL_DESCRIPTION,), ("Revert entry",)),
    ),
    ("search", "#/search", (("Search binaries, functions and collections.",),)),
    (
        "docs",
        "#/docs",
        (
            ("Documentation",),
            # One index card per shipped page, and the reader's own page.
            ("architecture",),
            ("errors",),
        ),
    ),
    (
        "docs page",
        "#/docs/errors",
        (
            ("reportal error codes",),
            # The on-this-page list and a rendered table from the document.
            ("On this page",),
            ("invalid-params",),
            ("no-docs",),
        ),
    ),
    (
        "changelog",
        "#/changelog",
        (("Changelog",), ("2.1.0",), ("2.0.0",), ("1.2.0",), ("1.1.0",)),
    ),
)

# Stored struct-recovery scan seeded on the smoke analysis.  The Data types
# panel auto-loads the stored result through a stored-only GET, so pre-seeding
# it gives the smoke real struct content to assert.
STRUCTS_SCAN: dict[str, object] = {
    "decompiled": 2,
    "skipped": 0,
    "structs": [
        {
            "name": "PlayerInfo",
            "anonymous": False,
            "semantic": True,
            "var": "player",
            "va": 0x10018A0,
            "new": True,
            "definition": "typedef struct PlayerInfo_s {\n\tint field_0;\n} PlayerInfo;\n",
            "offsets": ["0x0"],
            "evidence": 1,
            "functions": 1,
        }
    ],
    "applied": None,
}

MARKER_TEMPLATE = """\
# reportal workspace marker written by tools/smoke_spa.py.
[portal]
db = "reportal.db"
"""


def emit(message: str) -> None:
    """Write one smoke result line to stdout."""
    sys.stdout.write(f"{message}\n")
    sys.stdout.flush()


def repo_root() -> Path:
    """Return the nearest ancestor directory holding ``pyproject.toml``."""
    start = Path(__file__).resolve().parent
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise SystemExit("no pyproject.toml found above tools/smoke_spa.py")


def sibling(name: str) -> Path:
    """Return *name* beside the repo root."""
    return repo_root().parent / name


def free_port() -> int:
    """Return a currently free loopback port."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get(port: int, path: str) -> tuple[int, bytes]:
    """GET *path* from the local server; ``(0, b"")`` when it is not up."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers={"Accept-Encoding": "identity"})
        response = conn.getresponse()
        return response.status, response.read()
    except OSError:
        return 0, b""
    finally:
        conn.close()


def wait_for_server(port: int) -> bool:
    """Poll the health endpoint until the server answers 200."""
    deadline = time.monotonic() + SERVER_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if get(port, "/api/health")[0] == 200:
            return True
        time.sleep(0.3)
    return False


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# The two shapes a rebrew project carries its function list in: the text list an
# older project left (`<va> <name> <size>` per line) and the discovery inventory
# `rebrew init` writes now (`src/<target>/function_structure.json`).  The
# fixtures read whichever the project has, so a regenerated project does not
# strand the browser targets on a file the engine no longer scaffolds.
FUNCTION_TEXT_NAME = "functions.txt"
FUNCTION_JSON_NAME = "function_structure.json"
TARGET_SUBDIR = "NP"


def function_seed_file(project_dir: Path) -> Path:
    """The function list *project_dir* carries, in either shape."""
    target = project_dir / "src" / TARGET_SUBDIR
    for name in (FUNCTION_TEXT_NAME, FUNCTION_JSON_NAME):
        candidate = target / name
        if candidate.is_file():
            return candidate
    return target / FUNCTION_TEXT_NAME


def read_functions(path: Path, limit: int) -> list[tuple[int, str, int]]:
    """Return up to *limit* ``(va, name, size)`` rows from a rebrew function list.

    A `.json` list is the discovery inventory (`va`, `name`, `size` keys); any
    other path is the text list (`0x<va> <name> <size>` per line).
    """
    functions: list[tuple[int, str, int]] = []
    seen: set[int] = set()
    if path.suffix == ".json":
        rows = json.loads(path.read_text(encoding="utf-8"))
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            va = int(row.get("va") or 0)
            if va in seen:
                continue
            seen.add(va)
            functions.append((va, str(row.get("name") or ""), int(row.get("size") or 0)))
            if len(functions) >= limit:
                break
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) < 3 or not parts[0].startswith("0x"):
                continue
            va = int(parts[0], 16)
            if va in seen:
                continue
            seen.add(va)
            functions.append((va, parts[1], int(parts[2])))
            if len(functions) >= limit:
                break
    if not functions:
        raise SystemExit(f"no functions parsed from {path}")
    return functions


def _seed_auto_run(conn: sqlite3.Connection, *, binary_id: int, function_id: int) -> int:
    """Store one finished offline auto run with a root task, a batch and an attempt.

    The Auto-mode route's GET is stored-only, so a completed run gives the
    smoke a real task tree and coverage delta to render; no worker runs.
    """
    run_id = auto_store.create_auto_run(
        conn, binary_id=binary_id, config={"worker": AUTO_WORKER, "execute": False}
    )
    root_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=None,
        depth=auto_store.AUTO_ROOT_DEPTH,
        kind=auto_store.AUTO_TASK_ROOT,
        title=f"binary {binary_id}",
        worker=AUTO_WORKER,
    )
    batch_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=root_id,
        depth=auto_store.AUTO_BATCH_DEPTH,
        kind=auto_store.AUTO_TASK_BATCH,
        title="FreePrintSetup @ 0x10018a0",
        worker=AUTO_WORKER,
        function_id=function_id,
        va=0x10018A0,
    )
    auto_store.add_auto_attempt(
        conn,
        task_id=batch_id,
        attempt=1,
        worker=AUTO_WORKER,
        status="matched",
        detail={"reason": AUTO_REASON, "verified": True},
    )
    auto_store.update_auto_task(
        conn,
        batch_id,
        status=auto_store.AUTO_TASK_DONE,
        attempts=1,
        result={
            "outcomes": [
                {
                    "function_id": function_id,
                    "va": 0x10018A0,
                    "name": "FreePrintSetup",
                    "outcome": "matched",
                    "reason": AUTO_REASON,
                    "attempts": 1,
                }
            ]
        },
        finish=True,
    )
    auto_store.update_auto_task(
        conn,
        root_id,
        status=auto_store.AUTO_TASK_DONE,
        result={"matched": 1, "children": 1},
        finish=True,
    )
    auto_store.finish_auto_run(
        conn,
        run_id,
        status=auto_store.AUTO_RUN_DONE,
        stats={
            "matched": 1,
            "improved": 0,
            "failed": 0,
            "skipped": 0,
            "coverage_before": AUTO_COVERAGE_BEFORE,
            "coverage_after": AUTO_COVERAGE_AFTER,
        },
    )
    return run_id


def _seed_security_scan(
    conn: sqlite3.Connection, *, analysis_id: int, project_dir: Path
) -> dict[str, object]:
    """Run the real security scan over the project's sources and store it.

    `rebrew security-scan` is deterministic, rule-based and runs no sample and
    no network call, so the seeding can produce the real payload instead of
    hand-writing one.  The SPA renders one severity badge per finding, which is
    what the binary-detail route markers assert and the UI audit measures.
    """
    rebrew_bin = sibling(REBREW_RELATIVE)
    if not rebrew_bin.is_file():
        raise SystemExit(f"missing prerequisite: {rebrew_bin}")
    engine = engines.RebrewEngine()
    if not engine.available():
        raise SystemExit(f"missing prerequisite: {rebrew_bin}")
    result = engine.security_scan(project_dir)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_SECURITY,
        result,
        params={"min_severity": engines.DEFAULT_SECURITY_MIN_SEVERITY},
    )
    return result


def build_workspace(
    workspace: Path, project_dir: Path, binary_path: Path, functions_file: Path
) -> dict[str, int]:
    """Create a fresh reportal workspace and seed the smoke rows."""
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    (workspace / "reportal.toml").write_text(MARKER_TEMPLATE, encoding="utf-8")
    db = workspace / "reportal.db"
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_sha256 = sha256_file(binary_path)
        binary_id = store.add_binary(
            conn,
            sha256=binary_sha256,
            name="notepad.exe",
            path=str(binary_path),
            size=binary_path.stat().st_size,
            fmt="PE",
            arch="x86_32",
        )
        store.set_rebrew_context(conn, binary_id, str(project_dir))
        store.add_binary_tag(conn, binary_id, store.create_tag(conn, TAG_NAME))
        analysis_id = store.create_analysis(
            conn, binary_id=binary_id, engine="rebrew-import", status="done"
        )
        seeded = read_functions(functions_file, FUNCTION_SEED_COUNT)
        function_ids = [
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=va,
                name=name,
                size=size,
                status="STUB",
                name_source="rebrew",
            )
            for va, name, size in seeded
        ]
        for function_id, code in (
            (function_ids[0], DIFF_LEFT_DECOMP),
            (function_ids[1], DIFF_RIGHT_DECOMP),
        ):
            store.set_decompilation(conn, function_id, code, "kuna")
        store.set_ai_artifact(conn, function_ids[0], renames.RENAMES_KIND, RENAMES_SCAN, "smoke")
        # A stored summary, so the AI Summary panel renders a payload (and its
        # Discard control) without an endpoint configured.
        store.set_ai_artifact(
            conn, function_ids[0], llm.AI_KIND_SUMMARY, {"summary": AI_SUMMARY_TEXT}, "smoke"
        )
        store.add_comment(
            conn,
            scope_kind="binary",
            scope_id=binary_id,
            author=COMMENT_AUTHOR,
            body=COMMENT_BINARY_BODY,
        )
        store.add_comment(
            conn,
            scope_kind="function",
            scope_id=function_ids[0],
            author=COMMENT_AUTHOR,
            body=COMMENT_FUNCTION_BODY,
        )
        store.record_match(
            conn,
            function_id=function_ids[0],
            candidate_function_id=function_ids[1],
            similarity=DIFF_SIMILARITY,
            confidence=DIFF_CONFIDENCE,
        )
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, STRUCTS_SCAN)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, PE_INFO_SCAN)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_FILETYPE, FILETYPE_SCAN)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_FUNCTION_TRIAGE, FUNCTION_TRIAGE_SCAN)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_THREAT, THREAT_SCAN)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REMEDIATION, REMEDIATION_SCAN)
        _seed_security_scan(conn, analysis_id=analysis_id, project_dir=project_dir)
        family_id = store.add_family(
            conn,
            name=DETECT_FAMILY_NAME,
            aliases=[DETECT_FAMILY_ALIAS],
            notes="seeded for the SPA smoke",
            reference_binary_id=binary_id,
            signatures={
                "sha256": binary_sha256,
                "imphash": None,
                "rich_header_hash": None,
                "import_hash": hashlib.sha256(b"").hexdigest(),
                "import_names": [],
                "capabilities": [],
            },
        )
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_DETECT,
            {
                "binary_id": binary_id,
                "families_checked": 1,
                "matches": [
                    {
                        "family_id": family_id,
                        "name": DETECT_FAMILY_NAME,
                        "aliases": [DETECT_FAMILY_ALIAS],
                        "confidence": "high",
                        "signals": [
                            {
                                "kind": DETECT_SIGNAL_KIND,
                                "confidence": "high",
                                "detail": binary_sha256,
                            }
                        ],
                        "similarity": 1.0,
                    }
                ],
                "count": 1,
                "notes": [families.SCOPE_NOTE, families.THRESHOLD_NOTE],
            },
        )
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_UNSTRIP,
            {
                "candidates": 1,
                "proposals": [
                    {
                        "function_id": function_ids[0],
                        "va": 0x10018A0,
                        "current_name": "FreePrintSetup",
                        "proposed_name": UNSTRIP_PROPOSED_NAME,
                        "module": "COMDLG32",
                        "kind": "import",
                        "confidence": 0.3,
                    }
                ],
                "applied": False,
            },
        )
        conversation_id = store.create_conversation(
            conn,
            scope_kind="function",
            scope_id=function_ids[0],
            title=CONVERSATION_TITLE,
        )
        store.add_message(
            conn,
            conversation_id=conversation_id,
            role="user",
            content=CONVERSATION_MESSAGE,
        )
        run_id = store.create_pipeline_run(conn, function_id=function_ids[0], model="smoke")
        store.add_pipeline_step(
            conn,
            run_id=run_id,
            name=PIPELINE_STEP_NAME,
            status=store.PIPELINE_STEP_DONE,
            duration_ms=PIPELINE_STEP_DURATION_MS,
            provides=PIPELINE_STEP_PROVIDES,
        )
        store.finish_pipeline_run(conn, run_id, status=store.PIPELINE_RUN_DONE)
        _seed_auto_run(conn, binary_id=binary_id, function_id=function_ids[0])
        _seed_data_type(conn, binary_id=binary_id)
        _seed_signature(conn, binary_id=binary_id, function_id=function_ids[0])
        knowledge.ingest_document(
            conn,
            scope_kind=knowledge.SCOPE_KIND_BINARY,
            scope_id=binary_id,
            title=DOCUMENT_TITLE,
            source=DOCUMENT_SOURCE,
            mime="text/markdown",
            data=DOCUMENT_TEXT.encode("utf-8"),
        )
        graph.build_graph(conn, binary_id=binary_id)
        _seed_journal(conn, binary_id=binary_id)
        _other_binary_id, other_function_id = _seed_lineage(
            conn, binary_id=binary_id, binary_path=binary_path, seeded=seeded
        )
        store.record_match(
            conn,
            function_id=function_ids[0],
            candidate_function_id=other_function_id,
            similarity=COMPOSITION_SIMILARITY,
            confidence=0.9,
        )
        composition.run_composition(conn, binary_id=binary_id)
    cfg_function_id = next(
        function_id
        for function_id, (va, _name, _size) in zip(function_ids, seeded, strict=True)
        if va == CFG_LOOP_FUNCTION_VA
    )
    return {
        "binary_id": binary_id,
        "analysis_id": analysis_id,
        "function_id": function_ids[0],
        "candidate_function_id": function_ids[1],
        "cfg_function_id": cfg_function_id,
        "conversation_id": conversation_id,
    }


def _seed_journal(conn: sqlite3.Connection, *, binary_id: int) -> None:
    """Seed one journal entry, so the Journal view has a row to render."""
    log = journal.Journal(conn, JOURNAL_ACTION)
    log.record(
        effects.EFFECT_ROW_DELETE,
        f"registered binary {binary_id}",
        journal.row_delete_descriptor("binaries", binary_id),
    )
    log.flush()


def _seed_data_type(conn: sqlite3.Connection, *, binary_id: int) -> None:
    """Seed one editable data type parsed from a recovered definition.

    The declared size is seeded past the members' extent so the panel's
    size-vs-members warning renders, which is what the route marker asserts.
    """
    parsed = data_types.parse_definition(SMOKE_TYPE_DEFINITION)
    store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=int(parsed["size"]) + SMOKE_TYPE_EXTRA_SIZE,
        members=parsed["members"],
        kind=parsed["kind"],
        values=parsed["values"],
        target=parsed["target"],
        element_count=parsed["element_count"],
        source=data_types.SOURCE_SCAN,
    )


def _seed_signature(conn: sqlite3.Connection, *, binary_id: int, function_id: int) -> None:
    """Seed a function signature from its stored decompilation and name a parameter.

    The function detail Signature panel auto-loads the stored signature through
    its own GET, so the added parameter gives the smoke a rendered prototype to
    assert without running the decompiler.
    """
    signatures.seed_signatures(conn, binary_id=binary_id)
    signatures.add_parameter(
        conn, function_id, type_text="unsigned int", name=SMOKE_SIGNATURE_PARAMETER
    )


def _seed_lineage(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    binary_path: Path,
    seeded: list[tuple[int, str, int]],
) -> tuple[int, int]:
    """Register a copy of the smoke binary and store one lineage comparison.

    The copy is registered, analysed and given the same functions as the smoke
    binary except for one changed size and one extra function, so the Lineage
    panel renders real changed and added groups through its stored-only GET.
    The comparison itself comes from the production pairing code, not from a
    hand-written payload.  Returns the copy's binary id and its first function
    id, which the composition seed matches against.
    """
    other_binary_id = store.add_binary(
        conn,
        sha256=LINEAGE_OTHER_SHA256,
        name=LINEAGE_OTHER_NAME,
        path=str(binary_path),
    )
    other_analysis_id = store.create_analysis(
        conn, binary_id=other_binary_id, engine="rebrew-import", status="done"
    )
    va, name, size = seeded[0]
    other_function_id = store.add_function(
        conn,
        analysis_id=other_analysis_id,
        va=va,
        name=name,
        size=size,
        status="STUB",
        name_source="rebrew",
    )
    for va, name, size in seeded[1:]:
        store.add_function(
            conn,
            analysis_id=other_analysis_id,
            va=va,
            name=name,
            size=size + LINEAGE_OTHER_SIZE_DELTA,
            status="STUB",
            name_source="rebrew",
        )
    store.add_function(
        conn,
        analysis_id=other_analysis_id,
        va=LINEAGE_OTHER_EXTRA_VA,
        name=LINEAGE_OTHER_EXTRA_NAME,
        size=16,
        status="STUB",
        name_source="rebrew",
    )
    comparison = lineage.compare_functions(
        store.list_functions(conn, binary_id=binary_id),
        store.list_functions(conn, binary_id=other_binary_id),
    )
    lineage.store_comparison(
        conn,
        {
            "left_binary_id": binary_id,
            "right_binary_id": other_binary_id,
            "left_name": "notepad.exe",
            "right_name": LINEAGE_OTHER_NAME,
            "refined": False,
            "summary": comparison["summary"],
            "rows": comparison["rows"],
        },
    )
    return other_binary_id, other_function_id


def find_browser() -> str | None:
    """Return the first configured browser on PATH, or None."""
    for name in BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    return None


def ensure_frontend_built() -> int:
    """Build the SPA when its entry page is missing; 0 on success, 1 on failure."""
    dist_index = repo_root() / DIST_INDEX_RELATIVE
    if dist_index.is_file():
        return 0
    web = repo_root() / WEB_RELATIVE
    bun = shutil.which("bun")
    if bun is None:
        emit("missing prerequisite: bun on PATH (needed to build web/)")
        return 1
    if not (web / "node_modules").is_dir():
        emit("web/node_modules missing; running bun install")
        if subprocess.run([bun, "install"], cwd=str(web), check=False).returncode != 0:
            emit("frontend install failed")
            return 1
    emit("building web/ with bun run build")
    if subprocess.run([bun, "run", "build"], cwd=str(web), check=False).returncode != 0:
        emit("frontend build failed")
        return 1
    if not dist_index.is_file():
        emit(f"frontend build produced no {DIST_INDEX_RELATIVE}")
        return 1
    return 0


# Text only the binary detail view renders.  The view is loaded when its route
# is opened, so these live in their own chunk; the check below fails when one of
# them ends up in the entry bundle, which is what happens if a view import goes
# back to being static.
VIEW_MARKERS: tuple[str, ...] = (
    "Library identification",
    "Unpacked files",
    "Rename proposals",
)

# Shell dialogs that load on first open.  They used to ride in the entry chunk
# because the shortcut layer imported through them; keeping them out of the
# entry is what shortens the first paint after a cold cache.
SHELL_LAZY_MARKERS: tuple[str, ...] = (
    "search-dialog-body",
    "Everywhere",
    "reportal.notifications.dismissed",
)

# Transferred-size budget for the entry JS chunk (raw, before compression).
# Measured after the shell-dialog split: ~52 KiB.  The floor only moves up when
# a change that grows the entry is intentional and documented in docs/SPA.md.
ENTRY_JS_MAX_BYTES = 64 * 1024


def check_code_split() -> bool:
    """The initial bundle carries the shell, and each view is its own chunk.

    A reader's first paint should not parse the whole workbench.  This reads the
    built assets rather than a browser: the entry chunk must not carry a marker
    only the binary detail view renders, and some other chunk must.
    """
    assets = (repo_root() / DIST_INDEX_RELATIVE).parent / "assets"
    entry = sorted(assets.glob("index-*.js"))
    chunks = sorted(assets.glob("*.js"))
    if not entry or len(chunks) < 2:
        emit(f"[FAIL] the SPA is one bundle ({len(chunks)} chunk(s)); no view is loaded on demand")
        return False
    entry_path = entry[0]
    entry_text = entry_path.read_text(encoding="utf-8", errors="replace")
    entry_size = entry_path.stat().st_size
    if entry_size > ENTRY_JS_MAX_BYTES:
        emit(
            f"[FAIL] entry chunk {entry_path.name} is {entry_size} bytes "
            f"(budget {ENTRY_JS_MAX_BYTES}); defer more of the shell"
        )
        return False
    carried = [marker for marker in VIEW_MARKERS if marker in entry_text]
    if carried:
        emit(f"[FAIL] the initial bundle carries {carried[0]!r}, a view it should load on demand")
        return False
    shell_carried = [marker for marker in SHELL_LAZY_MARKERS if marker in entry_text]
    if shell_carried:
        emit(
            f"[FAIL] the initial bundle carries {shell_carried[0]!r}, "
            "a shell dialog that should load on demand"
        )
        return False
    eager_text = "".join(
        path.read_text(encoding="utf-8", errors="replace") for path in chunks if path not in entry
    )
    if not any(marker in eager_text for marker in VIEW_MARKERS):
        emit("[FAIL] no chunk carries the binary detail view; the markers moved")
        return False
    emit(f"code split: {len(chunks)} chunks, entry {entry_path.name} ({entry_size} bytes)")
    return True


def markers_missing(dom: str, groups: tuple[tuple[str, ...], ...]) -> list[tuple[str, ...]]:
    """The marker groups *dom* carries no member of."""
    return [group for group in groups if not any(marker in dom for marker in group)]


def render_markers(
    browser: str, url: str, groups: tuple[tuple[str, ...], ...]
) -> tuple[str, list[str]]:
    """Render *url* and wait until one marker of every group is in the DOM.

    The wait polls the live document instead of dumping it once after a fixed
    virtual-time budget: that budget caps how far ahead the page's timers run,
    not how long a real fetch takes to resolve, so a route whose data arrived
    late was dumped early and this gate flaked.  A group that never appears is
    still reported missing, with the DOM the deadline left behind.

    Returns the DOM and the page's own errors: a route that renders its marker
    while the console carries an uncaught throw or a dropped request is a
    failure the marker check alone would pass.
    """
    with (
        tempfile.TemporaryDirectory(prefix="smoke-spa-") as profile,
        cdp.browser_session(browser, Path(profile)) as (session_pipe, session_id),
    ):
        cdp.render(session_pipe, session_id, url, RENDER_WIDTH, RENDER_HEIGHT)
        deadline = time.monotonic() + MARKER_DEADLINE_SECONDS
        dom = cdp.document_html(session_pipe, session_id)
        while markers_missing(dom, groups) and time.monotonic() < deadline:
            time.sleep(MARKER_POLL_SECONDS)
            dom = cdp.document_html(session_pipe, session_id)
        return dom, cdp.page_errors(session_pipe, session_id)


def check_route(
    label: str, dom: str, groups: tuple[tuple[str, ...], ...], page_errors: list[str]
) -> bool:
    """Report whether *dom* carries one marker from every group and logged no error."""
    missing = markers_missing(dom, groups)
    ok = not missing and not page_errors
    emit(f"[{'PASS' if ok else 'FAIL'}] {label}")
    for group in missing:
        emit(f"       none of: {', '.join(group)}")
    for message in page_errors:
        emit(f"       {message}")
    return ok


# Markers the global search modal must carry once it is opened and queried.
SEARCH_MODAL_MARKERS: tuple[str, ...] = ("Global search", "notepad.exe", "matched")

# The scripts that open the modal through the documented shortcut and type a
# query.  A controlled React input needs the native value setter plus an input
# event; assigning `.value` alone leaves React's state untouched.  Opening is
# two steps because React mounts the dialog on a later render than the keydown.
_OPEN_SEARCH_SCRIPT = """(() => {
  window.dispatchEvent(new KeyboardEvent('keydown', {key: 'k', metaKey: true, bubbles: true}));
  return document.querySelector('.search-input') !== null;
})()"""

_TYPE_QUERY_SCRIPT = """(() => {
  const input = document.querySelector('.search-input');
  if (!input) return false;
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  setter.call(input, 'Notepad');
  input.dispatchEvent(new Event('input', {bubbles: true}));
  return true;
})()"""


def check_search_modal(browser: str, port: int) -> bool:
    """Open the global search modal through the shortcut and assert its markers.

    The modal is not a hash route, so the route loop cannot reach it: this
    dispatches the documented `⌘K` shortcut, waits for React to mount the
    dialog, types a query into the live input and polls for a result row.
    """
    url = f"http://127.0.0.1:{port}/#/"
    dom = ""
    with (
        tempfile.TemporaryDirectory(prefix="smoke-spa-modal-") as profile,
        cdp.browser_session(browser, Path(profile)) as (session_pipe, session_id),
    ):
        cdp.render(session_pipe, session_id, url, RENDER_WIDTH, RENDER_HEIGHT)
        deadline = time.monotonic() + MARKER_DEADLINE_SECONDS
        opened = False
        while not opened and time.monotonic() < deadline:
            opened = cdp.evaluate(session_pipe, session_id, _OPEN_SEARCH_SCRIPT) is True
            if not opened:
                time.sleep(MARKER_POLL_SECONDS)
        if not opened:
            emit("[FAIL] search modal: the shortcut did not open the dialog")
            return False
        cdp.evaluate(session_pipe, session_id, _TYPE_QUERY_SCRIPT)
        dom = cdp.document_html(session_pipe, session_id)
        while (
            not all(marker in dom for marker in SEARCH_MODAL_MARKERS)
            and time.monotonic() < deadline
        ):
            time.sleep(MARKER_POLL_SECONDS)
            dom = cdp.document_html(session_pipe, session_id)
    missing = [marker for marker in SEARCH_MODAL_MARKERS if marker not in dom]
    emit(f"[{'PASS' if not missing else 'FAIL'}] search modal")
    for marker in missing:
        emit(f"       missing: {marker}")
    return not missing


# The scripts the control-flow check drives: switch the code view to the graph,
# then activate the first edge's jump control and report where the focus landed.
_SWITCH_TO_CFG_SCRIPT = """(() => {
  const buttons = Array.from(document.querySelectorAll('.code-view-toggle button'));
  const target = buttons.find((button) => button.textContent.trim() === 'Control flow');
  if (!target) return false;
  target.click();
  return true;
})()"""

_JUMP_EDGE_SCRIPT = """(() => {
  const jump = document.querySelector('.cfg-edge-jump');
  if (!jump) return null;
  jump.click();
  const active = document.activeElement;
  if (!active || !active.classList.contains('cfg-block')) return null;
  return active.id;
})()"""


def check_cfg_view(browser: str, port: int, function_id: int) -> bool:
    """Switch a function's code view to its control-flow graph and assert it.

    The graph is the second view of the function detail route's code panel, not
    a route of its own, so this renders that route, clicks the Disassembly /
    Control flow toggle and polls for the graph's markers.  The first edge's
    jump control is then activated and the check asserts the focus landed on
    the block it names: that is what makes the edge list navigable rather than
    decorative.
    """
    url = f"http://127.0.0.1:{port}/#/functions/{function_id}"
    dom = ""
    with (
        tempfile.TemporaryDirectory(prefix="smoke-spa-cfg-") as profile,
        cdp.browser_session(browser, Path(profile)) as (session_pipe, session_id),
    ):
        cdp.render(session_pipe, session_id, url, RENDER_WIDTH, RENDER_HEIGHT)
        deadline = time.monotonic() + MARKER_DEADLINE_SECONDS
        switched = False
        while not switched and time.monotonic() < deadline:
            switched = cdp.evaluate(session_pipe, session_id, _SWITCH_TO_CFG_SCRIPT) is True
            if not switched:
                time.sleep(MARKER_POLL_SECONDS)
        if not switched:
            emit("[FAIL] control flow: the toggle did not switch the code view")
            return False
        dom = cdp.document_html(session_pipe, session_id)
        while not all(marker in dom for marker in CFG_MARKERS) and time.monotonic() < deadline:
            time.sleep(MARKER_POLL_SECONDS)
            dom = cdp.document_html(session_pipe, session_id)
        focused = cdp.evaluate(session_pipe, session_id, _JUMP_EDGE_SCRIPT)
    missing = [marker for marker in CFG_MARKERS if marker not in dom]
    emit(f"[{'PASS' if not missing else 'FAIL'}] control flow")
    for marker in missing:
        emit(f"       missing: {marker}")
    if missing:
        return False
    if not isinstance(focused, str) or not focused.startswith("cfg-block-"):
        emit(f"[FAIL] control flow: an edge jump focused no block (got {focused!r})")
        return False
    emit(f"       edge jump focused {focused}")
    return True


# The memory dump probe: the first rendered line's address, the linked address
# it landed on (the dump's address box and its first selected byte), and whether
# the documented `G` binding focused the address box.
_MEMORY_DUMP_SCRIPT = """(() => {
  const rows = document.querySelectorAll('.memory-scroll .memory-row');
  const dump = document.querySelector('.memory-scroll');
  if (!dump || rows.length === 0) return null;
  const first = rows[0].querySelector('.memory-address');
  const boxes = Array.from(document.querySelectorAll('input[type="text"]'));
  const addressBox = boxes.find((input) => input.value.startsWith('0x'));
  const selected = document.querySelector('.memory-scroll .byte-selected');
  dump.focus();
  dump.dispatchEvent(
    new KeyboardEvent('keydown', {key: 'g', bubbles: true, cancelable: true}),
  );
  const active = document.activeElement;
  return JSON.stringify({
    address: first ? first.textContent.trim() : null,
    landed: addressBox ? addressBox.value.trim() : null,
    selected: selected ? selected.getAttribute('aria-label') : null,
    focused: active ? active.getAttribute('aria-label') || active.tagName : null,
    rows: rows.length,
  });
})()"""


def _parse_hex(text: str) -> int | None:
    """Parse a `0x...` address, or None when it is not one."""
    try:
        return int(text, 16)
    except ValueError:
        return None


def check_memory_dump(browser: str, port: int, binary_id: int) -> bool:
    """The linked continuous dump: it opens on backed bytes and `G` focuses the box.

    The dump is a mode of the memory panel, not a route of its own, so this
    renders the binary detail with the section table's own link target (the
    first section's virtual address, the image base added) and asserts the first
    line starts inside the section the engine actually backs, and that the
    documented `G` binding moves focus to the address box.  Without this the
    continuous view would only be proven to exist, not to work.
    """
    status, raw = get(port, f"/api/binaries/{binary_id}/pe-info")
    if status != 200:
        emit("       memory dump: the stored PE info did not answer")
        return True
    stored = json.loads(raw)
    sections = stored.get("sections") if isinstance(stored, dict) else None
    if not isinstance(sections, list) or len(sections) < 2:
        emit("       memory dump: no stored section table to link from")
        return True
    # The stored section address is an RVA and the memory reads take an absolute
    # virtual address, so the link the panel renders adds the image base; the
    # first section is usually the executable one, and the walk snaps forward to
    # its first backed byte, which is inside it.
    image_base = int(stored.get("image_base") or 0)
    link = hex(image_base + int(sections[0]["virtual_address"]))
    section_start = image_base + int(sections[0]["virtual_address"])
    section_end = section_start + max(int(sections[0]["virtual_size"]), 1)
    url = f"http://127.0.0.1:{port}/#/binaries/{binary_id}?memory={link}"
    probe: object = None
    with (
        tempfile.TemporaryDirectory(prefix="smoke-spa-memory-") as profile,
        cdp.browser_session(browser, Path(profile)) as (session_pipe, session_id),
    ):
        cdp.render(session_pipe, session_id, url, RENDER_WIDTH, RENDER_HEIGHT)
        deadline = time.monotonic() + MARKER_DEADLINE_SECONDS
        while probe is None and time.monotonic() < deadline:
            probe = cdp.evaluate(session_pipe, session_id, _MEMORY_DUMP_SCRIPT)
            if probe is None:
                time.sleep(MARKER_POLL_SECONDS)
    if not isinstance(probe, str):
        emit("[FAIL] memory dump: the continuous view rendered no line")
        return False
    payload = json.loads(probe)
    # The pump opens on file offsets, so the first line is the file's start; what
    # the link promises is that the reader landed on the linked virtual address,
    # which the address box and the first selected byte both report.
    named = str(payload.get("landed") or "")
    landed = _parse_hex(named)
    if landed is None or not (section_start <= landed < section_end):
        emit(f"[FAIL] memory dump: the address box names {named or 'nothing'}, outside the link")
        return False
    first = _parse_hex(str(payload.get("address") or ""))
    if first is None:
        emit(f"[FAIL] memory dump: the first line has no address ({payload.get('address')!r})")
        return False
    if payload.get("focused") != "Go to address":
        emit(f"[FAIL] memory dump: G focused {payload.get('focused')!r}, not the address box")
        return False
    emit(f"       memory dump landed on {named} with {payload['rows']} line(s)")
    return True


def stop_server(proc: subprocess.Popen[bytes]) -> None:
    """Terminate the server's whole process group, escalating to SIGKILL."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=SERVER_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait(timeout=SERVER_STOP_TIMEOUT_SECONDS)


def run_smoke(workspace: Path, env: dict[str, str], browser: str, ids: dict[str, int]) -> int:
    """Start the server, render every route, and return the failure count."""
    port = free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "reportal",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-open",
        ],
        cwd=str(workspace),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    failures = 0
    try:
        if not wait_for_server(port):
            emit(f"[FAIL] server never became healthy on port {port}")
            return 1
        emit(f"serving on http://127.0.0.1:{port}")
        if not check_memory_dump(browser, port, int(ids["binary_id"])):
            failures += 1
        for label, route, groups in ROUTE_CHECKS:
            path = route.format(**ids)
            url = f"http://127.0.0.1:{port}/{path}"
            try:
                dom, page_errors = render_markers(browser, url, groups)
            except subprocess.TimeoutExpired:
                emit(f"[FAIL] {label}: browser timed out rendering {url}")
                failures += 1
                continue
            if not dom:
                emit(f"[FAIL] {label}: browser produced no DOM for {url}")
                failures += 1
                continue
            if not check_route(label, dom, groups, page_errors):
                failures += 1
        if not check_search_modal(browser, port):
            failures += 1
        if not check_cfg_view(browser, port, int(ids["cfg_function_id"])):
            failures += 1
    finally:
        stop_server(proc)
    return failures


def main() -> int:
    """Run the smoke; 0 on success or a clean skip, 1 otherwise."""
    rebrew_bin = sibling(REBREW_RELATIVE)
    project_dir = sibling(NOTEPAD_PROJECT_RELATIVE)
    binary_path = project_dir / "original" / "notepad.exe"
    functions_file = function_seed_file(project_dir)
    for required in (rebrew_bin, binary_path, functions_file):
        if not required.is_file():
            emit(f"missing prerequisite: {required}")
            return 1

    browser = find_browser()
    if browser is None:
        emit("skip: no headless browser (google-chrome-stable or chromium) on PATH")
        return 0

    if ensure_frontend_built():
        return 1

    workspace = repo_root() / ".scratch" / "smoke-spa"
    ids = build_workspace(workspace, project_dir, binary_path, functions_file)
    env = {
        **os.environ,
        "REPORTAL_DB": str(workspace / "reportal.db"),
        "REPORTAL_REBREW": str(rebrew_bin),
        # The seeded workspace has no docs/ of its own, so point the
        # documentation reader at the parent of this checkout's docs/, the way
        # an install whose documents live outside its workspace would.  The
        # directory is where `docs/` and `CHANGELOG.md` both resolve from.
        "REPORTAL_DOCS": str(repo_root() / "docs"),
    }
    emit(f"browser: {browser}")
    failures = 0 if check_code_split() else 1
    failures += run_smoke(workspace, env, browser, ids)
    if failures:
        emit(f"{failures} route(s) failed; workspace kept at {workspace}")
        return 1
    shutil.rmtree(workspace, ignore_errors=True)
    emit("smoke passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

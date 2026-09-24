"""Tests for the decompiler round-trip scripts.

The scripts are a pure render of the stored analysis: no engine runs, no
state directory and no extra dependency.  The tests seed one binary with a
real name, a placeholder and an empty name, then check each format carries
only the real one, the API/CLI/MCP faces answer, and bad inputs refuse.  A
second seed adds a comment, an AI summary and a stored signature to check
every include combination, and the escaping tests read each script's
``FUNCTIONS`` literal back with ``ast`` to prove hostile text stays data.
"""

from __future__ import annotations

import ast
import itertools
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, decompiler_scripts, llm, mcp_server, store

runner = CliRunner()

# Text that breaks naive quoting in every format: both quote styles, a
# backslash, line breaks, a tab, a NUL, a Unicode line separator, Latin-1,
# CJK and an astral-plane character.
HOSTILE = 'it\'s "quoted" \\ back\\slash\nnew line\r\tend \x00   für 中 \U0001f600'

# A comment that would close a triple-quoted or single-quoted literal.
QUOTE_RUN = "''' \\'"

SUMMARY_TEXT = "Copies n bytes."
COMMENT_TEXT = "checked against the CRT"


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> int:
    """One binary with a named, a placeholder and an empty function."""
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    binary_id = store.add_binary(
        conn,
        sha256="ab" * 32,
        name="demo.exe",
        path=str(target),
        size=4096,
        fmt="PE",
        arch="x86_32",
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="memcpy", size=64, status="STUB"
    )
    store.add_function(
        conn, analysis_id=analysis_id, va=0x1010, name="sub_1010", size=64, status="STUB"
    )
    store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="", size=64, status="STUB")
    return binary_id


def _function_id(conn: sqlite3.Connection, binary_id: int, name: str) -> int:
    [row] = [row for row in store.list_functions(conn, binary_id=binary_id) if row["name"] == name]
    return int(row["id"])


def _seed_rich(conn: sqlite3.Connection, tmp_path: Path) -> int:
    """The plain seed plus a comment, an AI summary and a signature on ``memcpy``."""
    binary_id = _seed(conn, tmp_path)
    function_id = _function_id(conn, binary_id, "memcpy")
    store.add_comment(
        conn, scope_kind="function", scope_id=function_id, author="ana", body=COMMENT_TEXT
    )
    store.set_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, {"summary": SUMMARY_TEXT}, "m")
    store.upsert_signature(
        conn,
        function_id=function_id,
        name="memcpy",
        return_type="void *",
        calling_convention="cdecl",
        parameters=[
            {"index": 0, "type": "void *", "name": "dst", "at": "stack", "bits": 32},
            {"index": 1, "type": "unsigned int", "name": "n"},
        ],
    )
    return binary_id


def _python_functions(text: str) -> list[tuple[Any, ...]]:
    """The ``FUNCTIONS`` literal of a rendered script, read back as data."""
    compile(text, "<script>", "exec")
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "FUNCTIONS":
            return [tuple(row) for row in ast.literal_eval(node.value)]
    raise AssertionError("no FUNCTIONS literal in the script")


INCLUDE_SUBSETS = [
    subset
    for size in range(1, len(decompiler_scripts.INCLUDE_KINDS) + 1)
    for subset in itertools.combinations(decompiler_scripts.INCLUDE_KINDS, size)
]


class TestRender:
    def test_only_real_names_are_carried(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        for fmt in decompiler_scripts.SCRIPT_FORMATS:
            payload = decompiler_scripts.script(conn, binary_id, fmt=fmt)
            assert payload["renames"] == 1
            assert payload["functions"] == 3

    def test_ghidra_script_renames_by_entry_point(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="ghidra")["text"])
        assert _python_functions(text) == [(0x1000, "memcpy", None, None)]
        assert "getFunctionAt(address)" in text
        assert "sub_1010" not in text
        assert "SourceType.USER_DEFINED" in text

    def test_ida_script_is_idapython(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        # The file is saved as renames_ida.py, so it must be Python: IDC's
        # MakeName with `;` comment lines was a syntax error under IDAPython.
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="ida")["text"])
        assert "idc.set_name(va, name" in text
        assert _python_functions(text) == [(0x1000, "memcpy", None, None)]
        assert "sub_1010" not in text

    def test_binja_document_is_json(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="binja")["text"])
        document = json.loads(text)
        assert document["functions"] == [{"address": 0x1000, "name": "memcpy"}]
        assert document["include"] == ["renames"]

    @pytest.mark.parametrize(
        "name",
        ["__declspec", "__stdcall", "static", 'say "hi"', "int __stdcall f(void)", "a\nb", "  "],
    )
    def test_a_name_that_is_not_an_identifier_is_skipped(
        self, conn: sqlite3.Connection, tmp_path: Path, name: str
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        store.add_function(conn, analysis_id=analysis_id, va=0x3000, name=name, size=8)
        for fmt in decompiler_scripts.SCRIPT_FORMATS:
            assert decompiler_scripts.script(conn, binary_id, fmt=fmt)["renames"] == 1

    def test_carried_names(self) -> None:
        assert decompiler_scripts.is_carried_name("größe")
        assert decompiler_scripts.is_carried_name("?Bar@CFoo@@QAEXXZ")
        assert not decompiler_scripts.is_carried_name("FUN_00401000")
        assert not decompiler_scripts.is_carried_name("__declspec")

    @pytest.mark.parametrize("fmt", ["ghidra", "ida"])
    def test_hostile_text_round_trips_through_python_scripts(self, fmt: str) -> None:
        payload = {
            "binary_name": HOSTILE,
            "include": list(decompiler_scripts.INCLUDE_KINDS),
            "entries": [
                {"va": 0x1000, "name": "größe", "comment": HOSTILE, "prototype": None},
                {"va": 0x2000, "name": None, "comment": QUOTE_RUN, "prototype": "int f(void);"},
            ],
        }
        text = decompiler_scripts.render(payload, fmt=fmt)
        assert text.isascii()
        assert _python_functions(text) == [
            (0x1000, "größe", HOSTILE, None),
            (0x2000, None, QUOTE_RUN, "int f(void);"),
        ]
        # The binary name lands in a comment line and cannot open a new one.
        assert all(line.startswith("#") for line in text.splitlines()[:3])

    def test_hostile_text_round_trips_through_binja_json(self) -> None:
        payload = {
            "binary_name": HOSTILE,
            "include": ["renames", "comments"],
            "entries": [{"va": 0x1000, "name": "f", "comment": HOSTILE, "prototype": None}],
        }
        document = json.loads(decompiler_scripts.render(payload, fmt="binja"))
        assert document["binary"] == HOSTILE
        assert document["functions"] == [{"address": 0x1000, "name": "f", "comment": HOSTILE}]

    def test_python_literal_escapes(self) -> None:
        assert decompiler_scripts.python_literal("a'b") == "u'a\\'b'"
        assert decompiler_scripts.python_literal("ü中\U0001f600") == ("u'\\xfc\\u4e2d\\U0001f600'")
        assert decompiler_scripts.python_literal("\\\n") == "u'\\\\\\n'"

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        _seed(conn, tmp_path)
        try:
            decompiler_scripts.script(conn, 999, fmt="ghidra")
        except decompiler_scripts.ScriptError as exc:
            assert exc.code == "binary not found"
        else:  # pragma: no cover - the guard above must raise
            raise AssertionError("expected ScriptError")

    def test_unknown_format_is_rejected(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = decompiler_scripts.collect(conn, binary_id)
        try:
            decompiler_scripts.render(payload, fmt="radare2")
        except ValueError as exc:
            assert "unknown format" in str(exc)
        else:  # pragma: no cover - the guard above must raise
            raise AssertionError("expected ValueError")


class TestInclude:
    def test_parse_include(self) -> None:
        assert decompiler_scripts.parse_include(None) == ("renames",)
        assert decompiler_scripts.parse_include("") == ("renames",)
        assert decompiler_scripts.parse_include(" Summaries , renames,") == (
            "renames",
            "summaries",
        )
        assert decompiler_scripts.parse_include(["signatures", "comments"]) == (
            "comments",
            "signatures",
        )
        with pytest.raises(decompiler_scripts.ScriptError) as caught:
            decompiler_scripts.parse_include("renames,types")
        assert caught.value.code == "invalid include"
        assert "types" in caught.value.detail

    @pytest.mark.parametrize("include", INCLUDE_SUBSETS)
    def test_every_combination_carries_exactly_its_fields(
        self, conn: sqlite3.Connection, tmp_path: Path, include: tuple[str, ...]
    ) -> None:
        binary_id = _seed_rich(conn, tmp_path)
        comment_parts = []
        if "summaries" in include:
            comment_parts.append(f"AI summary: {SUMMARY_TEXT}")
        if "comments" in include:
            comment_parts.append(f"ana: {COMMENT_TEXT}")
        expected = (
            0x1000,
            "memcpy" if "renames" in include else None,
            "\n\n".join(comment_parts) or None,
            "void * __cdecl memcpy(void * dst, unsigned int n);"
            if "signatures" in include
            else None,
        )
        for fmt in ("ghidra", "ida"):
            result = decompiler_scripts.script(conn, binary_id, fmt=fmt, include=include)
            assert _python_functions(str(result["text"])) == [expected]
            assert result["include"] == list(include)
            assert result["renames"] == int(expected[1] is not None)
            assert result["comments"] == int(expected[2] is not None)
            assert result["prototypes"] == int(expected[3] is not None)
        document = json.loads(
            str(decompiler_scripts.script(conn, binary_id, fmt="binja", include=include)["text"])
        )
        carried = {
            key: value
            for key, value in zip(("name", "comment", "prototype"), expected[1:], strict=True)
            if value is not None
        }
        assert document["functions"] == [{"address": 0x1000, **carried}]

    def test_prototype_imports_only_when_a_prototype_is_carried(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_rich(conn, tmp_path)
        plain = str(decompiler_scripts.script(conn, binary_id, fmt="ghidra")["text"])
        typed = str(
            decompiler_scripts.script(conn, binary_id, fmt="ghidra", include=("signatures",))[
                "text"
            ]
        )
        assert "CParserUtils" not in plain
        assert "CParserUtils.parseSignature" in typed
        assert "setPlateComment(address, comment)" in plain

    @pytest.mark.parametrize(
        ("signature", "name"),
        [
            (None, "f"),
            ({"return_type": "", "parameters": []}, "f"),
            ({"return_type": "int", "parameters": [{"type": ""}]}, "f"),
            ({"return_type": "int", "parameters": [{"type": "int", "name": "a b"}]}, "f"),
            ({"return_type": "int (*)(void)", "parameters": []}, "f"),
            ({"return_type": "int\nsystem", "parameters": []}, "f"),
            ({"return_type": "int", "parameters": []}, "?Bar@CFoo@@QAEXXZ"),
            ({"return_type": "int", "parameters": []}, "größe"),
            ({"return_type": "int", "calling_convention": "std call", "parameters": []}, "f"),
        ],
    )
    def test_unsafe_prototypes_are_not_carried(
        self, signature: dict[str, Any] | None, name: str
    ) -> None:
        assert decompiler_scripts.safe_prototype(signature, name) is None

    def test_safe_prototype_drops_location_annotations(self) -> None:
        signature = {
            "return_type": "int",
            "calling_convention": "stdcall",
            "parameters": [{"type": "char *", "name": "s", "at": "ecx", "kind": "reg"}],
        }
        assert decompiler_scripts.safe_prototype(signature, "f") == "int __stdcall f(char * s);"

    def test_a_placeholder_still_carries_its_comment(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        store.add_comment(
            conn,
            scope_kind="function",
            scope_id=_function_id(conn, binary_id, "sub_1010"),
            author="",
            body="hot",
        )
        text = str(
            decompiler_scripts.script(conn, binary_id, fmt="ida", include=("renames", "comments"))[
                "text"
            ]
        )
        assert _python_functions(text) == [
            (0x1000, "memcpy", None, None),
            (0x1010, None, "hot", None),
        ]


class TestApi:
    def test_export_answers_a_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        status, _headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?format=ida"
        )
        assert status == "200 OK"
        assert b"idc.set_name" in body

    def test_export_threads_include(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_rich(conn, tmp_path)
        status, _headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?format=binja&include=summaries"
        )
        assert status == "200 OK"
        assert json.loads(body)["functions"] == [
            {"address": 0x1000, "comment": f"AI summary: {SUMMARY_TEXT}"}
        ]

    def test_export_refuses_an_unknown_include(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?include=types"
        )
        assert status == "400 Bad Request"
        assert json_body(body, headers)["error"] == "invalid include"

    def test_export_is_an_attachment_named_after_the_binary(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        store.rename_binary(conn, binary_id, 'we"ird/name.exe')
        for fmt, filename in (
            ("ghidra", "name_renames_ghidra.py"),
            ("ida", "name_renames_ida.py"),
            ("binja", "name_renames_binja.json"),
        ):
            status, headers, _body = wsgi_request(
                "GET", f"/api/binaries/{binary_id}/decompiler-script?format={fmt}"
            )
            assert status == "200 OK"
            assert headers["Content-Disposition"] == f'attachment; filename="{filename}"'

    def test_export_refuses_an_unknown_format(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?format=nope"
        )
        assert status == "400 Bad Request"
        assert json_body(body, headers)["error"] == "invalid format"

    def test_export_404s_an_unknown_binary(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/decompiler-script")
        assert status == "404 Not Found"
        assert json_body(body, headers)["error"] == "binary not found"


class TestCli:
    def test_command_prints_the_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "memcpy" in result.output

    def test_command_json_wraps_stdout_body(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["format"] == "ghidra"
        assert "memcpy" in payload["text"]

    def test_command_threads_include(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_rich(conn, tmp_path)
        result = runner.invoke(
            cli.app,
            [
                "decompiler-script",
                str(binary_id),
                "--format",
                "binja",
                "--include",
                "comments,signatures",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        document = json.loads(json.loads(result.stdout)["text"])
        assert document["functions"] == [
            {
                "address": 0x1000,
                "comment": f"ana: {COMMENT_TEXT}",
                "prototype": "void * __cdecl memcpy(void * dst, unsigned int n);",
            }
        ]

    def test_command_refuses_an_unknown_include(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id), "--include", "x"])
        assert result.exit_code != 0
        assert "invalid include" in result.output

    def test_command_refuses_an_unknown_format(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id), "--format", "nope"])
        assert result.exit_code != 0
        assert "format must be one of" in result.output

    def test_command_writes_a_file(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        out = tmp_path / "renames.py"
        result = runner.invoke(
            cli.app,
            ["decompiler-script", str(binary_id), "--output", str(out), "--json"],
        )
        assert result.exit_code == 0, result.output
        assert out.is_file()
        assert json.loads(result.output)["path"] == str(out)


class TestMcp:
    def test_tool_answers_the_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, failed = mcp_server.call_tool(
            "export_decompiler_script", {"binary_id": binary_id, "format": "ghidra"}
        )
        assert not failed
        assert payload["renames"] == 1

    def test_tool_threads_include(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_rich(conn, tmp_path)
        payload, failed = mcp_server.call_tool(
            "export_decompiler_script",
            {"binary_id": binary_id, "format": "ghidra", "include": ["signatures"]},
        )
        assert not failed
        assert (payload["renames"], payload["prototypes"]) == (0, 1)
        payload, failed = mcp_server.call_tool(
            "export_decompiler_script", {"binary_id": binary_id, "include": ["nope"]}
        )
        assert failed
        assert payload["error"] == "invalid include"

    def test_tool_refuses_an_unknown_format(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, failed = mcp_server.call_tool(
            "export_decompiler_script", {"binary_id": binary_id, "format": "nope"}
        )
        assert failed
        assert payload["error"] == "invalid format"

    def test_tool_404s_an_unknown_binary(self, conn: sqlite3.Connection) -> None:
        payload, failed = mcp_server.call_tool("export_decompiler_script", {"binary_id": 999})
        assert failed
        assert payload["error"] == "binary not found"

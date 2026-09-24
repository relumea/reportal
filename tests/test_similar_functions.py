"""The similar-functions query on every surface: the two routes, the MCP tool, the CLI.

Every test seeds a corpus of cached listings: a target function, its known
counterpart in another binary (the same listing with one instruction changed),
and unrelated functions.  The query path is the real scorer and the real LSH
index; code bytes go through the real engine's in-process disassembler.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, matching, mcp_server, similarity, store

pytestmark = pytest.mark.skipif(not similarity.available(), reason="similarity extra not installed")

runner = CliRunner()

TARGET = (
    "push ebp\nmov ebp, esp\nsub esp, 0x20\nmov eax, dword [ebp + 8]\ntest eax, eax\n"
    "je 0x401040\nmov ecx, dword [eax + 4]\nlea edx, [ecx + ecx*4]\nshl edx, 2\n"
    "add eax, edx\nmovzx ecx, byte [eax + 12]\ncmp ecx, 0x7f\njne 0x401030\n"
    "call 0x402000\nxor eax, eax\nleave\nret\n"
)
# One instruction differs: the counterpart a query for TARGET must rank first.
COUNTERPART = TARGET.replace("shl edx, 2", "shl edx, 3").replace("cmp ecx, 0x7f", "or ecx, ebx")
UNRELATED = (
    "fld dword [ebp - 8]\nfmul st0, st1\nfstp qword [esp]\ncall 0x403000\nret\n",
    "rep movsb\ncdq\nidiv ecx\nsar eax, 1\nret\n",
    "inc edi\ndec ecx\njnz 0x401000\nret\n",
)

# 32-bit x86: push ebp; mov ebp, esp; mov eax, [ebp+8]; add eax, 1; pop ebp; ret.
CODE_HEX = "5589e58b450883c0015dc3"
CODE_VA = 0x401000


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    ids: dict[str, int] = {}
    listings: dict[str, tuple[str, str]] = {
        "target": ("a.exe", TARGET),
        "counterpart": ("b.exe", COUNTERPART),
        "other0": ("a.exe", UNRELATED[0]),
        "other1": ("b.exe", UNRELATED[1]),
        "other2": ("b.exe", UNRELATED[2]),
    }
    analyses: dict[str, int] = {}
    for binary in ("a.exe", "b.exe"):
        binary_id = store.add_binary(conn, sha256=binary[0] * 64, name=binary)
        ids[binary] = binary_id
        analyses[binary] = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    for index, (name, (binary, text)) in enumerate(listings.items()):
        function_id = store.add_function(
            conn, analysis_id=analyses[binary], va=0x1000 + index * 0x100, name=name, size=32
        )
        assert store.set_disasm(conn, function_id, text)
        ids[name] = function_id
    return ids


def _post(path: str, body: Any) -> tuple[int, Any]:
    status, headers, raw = wsgi_request("POST", path, body=json.dumps(body))
    return int(status.split()[0]), json_body(raw, headers)


class TestStoredRoute:
    def test_the_counterpart_ranks_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post(f"/api/functions/{ids['target']}/similar", {})

        assert status == 200
        assert payload["function_id"] == ids["target"]
        assert payload["candidate_source"] == matching.CANDIDATES_FROM_INDEX
        assert payload["min_similarity"] == matching.DEFAULT_SIMILAR_MIN_SIMILARITY
        first = payload["hits"][0]
        assert first["function_id"] == ids["counterpart"]
        assert first["name"] == "counterpart"
        assert first["binary_id"] == ids["b.exe"]
        assert first["binary_name"] == "b.exe"
        assert first["similarity"] >= matching.DEFAULT_SIMILAR_MIN_SIMILARITY
        assert ids["target"] not in [hit["function_id"] for hit in payload["hits"]]

    def test_an_empty_body_takes_the_defaults(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, _headers, raw = wsgi_request("POST", f"/api/functions/{ids['target']}/similar")

        assert status.startswith("200")
        assert json.loads(raw)["limit"] == matching.DEFAULT_SIMILAR_LIMIT

    def test_a_low_floor_is_answered_pairwise(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post(
            f"/api/functions/{ids['target']}/similar", {"min_similarity": 50, "limit": 2}
        )

        assert status == 200
        assert payload["candidate_source"] == matching.CANDIDATES_PAIRWISE
        assert payload["hits"][0]["function_id"] == ids["counterpart"]
        assert len(payload["hits"]) <= 2

    def test_404_for_a_missing_function(self, portal_db: Path) -> None:
        status, payload = _post("/api/functions/9999/similar", {})

        assert status == 404
        assert payload["error"] == "function not found"

    @pytest.mark.parametrize(
        "body",
        [
            {"limit": 0},
            {"limit": matching.MAX_SIMILAR_LIMIT + 1},
            {"limit": True},
            {"min_similarity": 101},
            {"min_similarity": "high"},
            {"listing": TARGET},
        ],
    )
    def test_400_for_a_malformed_body(self, conn: sqlite3.Connection, body: Any) -> None:
        ids = _seed(conn)

        status, payload = _post(f"/api/functions/{ids['target']}/similar", body)

        assert status == 400
        assert payload["error"] == matching.INVALID_SIMILAR_QUERY
        assert payload["doc_url"].endswith("#invalid-similar-query")

    def test_400_without_a_listing_or_context(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.clear_disasm(conn, ids["target"])

        status, payload = _post(f"/api/functions/{ids['target']}/similar", {})

        assert status == 400
        assert payload["error"] == "no-engine-context"

    def test_503_without_the_extra(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        monkeypatch.setattr(similarity, "available", lambda: False)

        status, payload = _post(f"/api/functions/{ids['target']}/similar", {})

        assert status == 503
        assert payload["error"] == "similarity-unavailable"


class TestPastedRoute:
    def test_a_listing_ranks_its_counterpart_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _post("/api/functions/similar", {"listing": COUNTERPART})

        assert status == 200
        assert payload["function_id"] is None
        assert payload["hits"][0]["function_id"] == ids["counterpart"]
        assert payload["hits"][0]["similarity"] == 100.0
        assert payload["hits"][1]["function_id"] == ids["target"]

    def test_code_bytes_find_the_function_they_came_from(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        listing = engines.RebrewEngine().disassemble_bytes(
            bytes.fromhex(CODE_HEX), CODE_VA, "x86_32"
        )
        assert store.set_disasm(conn, ids["other2"], listing)

        status, payload = _post(
            "/api/functions/similar", {"bytes": CODE_HEX, "arch": "x86_32", "va": CODE_VA}
        )

        assert status == 200
        assert payload["hits"][0]["function_id"] == ids["other2"]
        assert payload["hits"][0]["similarity"] == 100.0

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"listing": ""},
            {"listing": "   \n"},
            {"listing": 7},
            {"listing": TARGET, "bytes": CODE_HEX, "arch": "x86_32"},
            {"listing": TARGET, "arch": "x86_32"},
            {"bytes": "zz", "arch": "x86_32"},
            {"bytes": "", "arch": "x86_32"},
            {"bytes": CODE_HEX},
            {"bytes": CODE_HEX, "arch": "vax"},
            {"bytes": CODE_HEX, "arch": "x86_32", "va": -1},
            {"bytes": "00" * (matching.MAX_QUERY_BYTES + 1), "arch": "x86_32"},
            {"listing": TARGET, "top": 3},
        ],
    )
    def test_400_for_a_malformed_query(self, portal_db: Path, body: Any) -> None:
        status, payload = _post("/api/functions/similar", body)

        assert status == 400
        assert payload["error"] == matching.INVALID_SIMILAR_QUERY

    def test_a_non_json_body_is_the_shared_400(self, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("POST", "/api/functions/similar", body="listing")

        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid JSON body"


class TestMcpTool:
    def test_a_stored_function_ranks_its_counterpart_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        payload, is_error = mcp_server.call_tool(
            "find_similar_functions", {"function_id": ids["target"], "limit": 3}
        )

        assert not is_error, payload
        assert payload["hits"][0]["function_id"] == ids["counterpart"]
        assert payload["limit"] == 3

    def test_a_pasted_listing(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        payload, is_error = mcp_server.call_tool(
            "find_similar_functions", {"listing": TARGET, "min_similarity": 90}
        )

        assert not is_error, payload
        assert payload["hits"][0]["function_id"] == ids["target"]

    def test_the_tool_never_runs_the_engine_for_a_stored_function(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        store.clear_disasm(conn, ids["target"])

        payload, is_error = mcp_server.call_tool(
            "find_similar_functions", {"function_id": ids["target"]}
        )

        assert is_error
        assert payload["error"] == "no-disasm"

    def test_a_malformed_query_is_a_tool_error(self, portal_db: Path) -> None:
        payload, is_error = mcp_server.call_tool("find_similar_functions", {"listing": ""})

        assert is_error
        assert payload["error"] == matching.INVALID_SIMILAR_QUERY

    def test_a_missing_function_is_a_tool_error(self, portal_db: Path) -> None:
        payload, is_error = mcp_server.call_tool("find_similar_functions", {"function_id": 999})

        assert is_error
        assert payload["error"] == "function not found"


class TestCli:
    def test_similar_ranks_the_counterpart_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        result = runner.invoke(cli.app, ["similar", str(ids["target"]), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["hits"][0]["function_id"] == ids["counterpart"]
        assert payload["candidate_source"] == matching.CANDIDATES_FROM_INDEX

    def test_similar_reads_a_listing_file(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = _seed(conn)
        listing = tmp_path / "query.asm"
        listing.write_text(COUNTERPART)

        result = runner.invoke(cli.app, ["similar", "--listing", str(listing), "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["hits"][0]["function_id"] == ids["counterpart"]

    def test_similar_human_output_names_the_hit(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        result = runner.invoke(cli.app, ["similar", str(ids["target"])])

        assert result.exit_code == 0, result.output
        assert "counterpart" in result.output
        assert "b.exe" in result.output

    @pytest.mark.parametrize(
        "args",
        [
            [],
            ["1", "--bytes", CODE_HEX],
            ["--bytes", CODE_HEX],
            ["--bytes", CODE_HEX, "--arch", "vax"],
            ["--arch", "x86_32", "1"],
            ["1", "--limit", "0"],
        ],
    )
    def test_similar_refuses_a_malformed_query(
        self, conn: sqlite3.Connection, args: list[str]
    ) -> None:
        _seed(conn)

        result = runner.invoke(cli.app, ["similar", *args, "--json"])

        assert result.exit_code == 1
        assert "error" in json.loads(result.stdout)

    def test_similar_unknown_function_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["similar", "999", "--json"])

        assert result.exit_code == 1
        assert "no function with id 999" in result.stdout

    def test_match_index_status_and_rebuild(self, conn: sqlite3.Connection) -> None:
        _seed(conn)

        before = runner.invoke(cli.app, ["match-index", "--json"])
        rebuilt = runner.invoke(cli.app, ["match-index", "rebuild", "--json"])
        human = runner.invoke(cli.app, ["match-index", "status"])

        assert before.exit_code == 0, before.output
        assert json.loads(before.stdout)["unindexed"] == 5
        assert rebuilt.exit_code == 0, rebuilt.output
        payload = json.loads(rebuilt.stdout)
        assert payload["indexed"] == 5
        assert payload["unindexed"] == 0
        assert human.exit_code == 0, human.output
        assert "5 functions indexed" in human.output

    def test_match_index_refuses_an_unknown_action(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["match-index", "drop", "--json"])

        assert result.exit_code == 1
        assert "unknown action" in json.loads(result.stdout)["error"]


class TestDisassembleBytes:
    def test_x86_32_code_is_nasm_source_like_a_cached_listing(self) -> None:
        listing = engines.RebrewEngine().disassemble_bytes(
            bytes.fromhex(CODE_HEX), CODE_VA, "x86_32"
        )

        assert listing.startswith("bits 32\norg 0x00401000\n")
        assert "push ebp" in listing
        assert "ret" in listing

    def test_another_isa_is_the_asm_listing(self) -> None:
        # stp x29, x30, [sp, #-0x10]! ; mov x29, sp
        listing = engines.RebrewEngine().disassemble_bytes(
            bytes.fromhex("fd7bbfa9fd030091"), 0, "arm64"
        )

        assert listing == "stp x29, x30, [sp, #-0x10]!\nmov x29, sp\n"

    def test_code_that_decodes_to_nothing_is_refused(self, portal_db: Path) -> None:
        # A lone ARM64 byte is shorter than one instruction.
        status, payload = _post("/api/functions/similar", {"bytes": "fd", "arch": "arm64"})

        assert status == 400
        assert payload["error"] == matching.INVALID_SIMILAR_QUERY
        assert "no instruction" in payload["detail"]

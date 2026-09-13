"""Tests for the function control-flow graph route."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request

from reportal import engines, store

PROJECT_DIR = "/projects/notepad-rebrew"

# An engine payload for `rebrew asm <va> --size N --format cfg --json`, shaped
# like the live contract: three blocks, one of them closing a loop through a
# labelled back edge.  Every address is the engine's `0x...` text.
CFG: dict[str, Any] = {
    "va": "0x1000",
    "size": 32,
    "block_count": 3,
    "block_total": 3,
    "block_cap": 512,
    "truncated": False,
    "note": None,
    "blocks": [
        {
            "va": "0x1000",
            "size": 12,
            "instruction_count": 4,
            "first": "push ebp",
            "last": "jne 0x100c",
        },
        {
            "va": "0x100c",
            "size": 8,
            "instruction_count": 3,
            "first": "mov eax, 1",
            "last": "ret",
        },
        {
            "va": "0x1014",
            "size": 12,
            "instruction_count": 4,
            "first": "inc ecx",
            "last": "jmp 0x1000",
        },
    ],
    "edges": [
        {"from": "0x1000", "to": "0x100c", "back_edge": False},
        {"from": "0x1014", "to": "0x1000", "back_edge": True},
    ],
}


def _seed(conn: sqlite3.Connection, *, project: bool = True) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="12" * 32, name="demo.exe", path="/x/demo.exe")
    if project:
        store.set_rebrew_context(conn, binary_id, PROJECT_DIR)
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=32, status="STUB"
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id}


def _install(
    monkeypatch: pytest.MonkeyPatch,
    fake_engine: FakeEngine,
    payload: dict[str, Any],
    calls: list[tuple[str, int, int]] | None = None,
) -> None:
    """Serve *payload* from the fake engine's CFG call, recording its arguments."""

    def control_flow_graph(project_dir: str | object, va: int, size: int = 0) -> dict[str, Any]:
        fake_engine.calls.append("control_flow_graph")
        if calls is not None:
            calls.append((str(project_dir), va, size))
        return payload

    monkeypatch.setattr(fake_engine, "control_flow_graph", control_flow_graph)


def _get(function_id: int) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", f"/api/functions/{function_id}/cfg")


class TestPayload:
    def test_every_address_is_an_int_not_a_hex_string(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(monkeypatch, fake_engine, CFG)
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        payload = json_body(body, headers)

        assert payload["function_id"] == ids["function"]
        assert payload["va"] == 0x1000
        assert [block["va"] for block in payload["blocks"]] == [0x1000, 0x100C, 0x1014]
        assert [(edge["from"], edge["to"]) for edge in payload["edges"]] == [
            (0x1000, 0x100C),
            (0x1014, 0x1000),
        ]

    def test_a_block_carries_its_size_count_and_instruction_text(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(monkeypatch, fake_engine, CFG)
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        assert json_body(body, headers)["blocks"][0] == {
            "va": 0x1000,
            "size": 12,
            "instruction_count": 4,
            "first": "push ebp",
            "last": "jne 0x100c",
        }

    def test_an_edge_carries_its_back_edge_flag(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(monkeypatch, fake_engine, CFG)
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        assert json_body(body, headers)["edges"] == [
            {"from": 0x1000, "to": 0x100C, "back_edge": False},
            {"from": 0x1014, "to": 0x1000, "back_edge": True},
        ]

    def test_the_counts_state_the_cap(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(monkeypatch, fake_engine, {**CFG, "truncated": True, "block_total": 9})
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        payload = json_body(body, headers)
        assert payload["block_count"] == len(payload["blocks"]) == 3
        assert payload["block_total"] == 9
        assert payload["block_cap"] == 512
        assert payload["truncated"] is True
        assert payload["size"] == 32

    def test_the_engine_note_is_passed_through(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        note = "function extent unresolved - pass --size"
        _install(monkeypatch, fake_engine, {**CFG, "note": note})
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        assert json_body(body, headers)["note"] == note

    def test_empty_blocks_carry_a_reason(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(
            monkeypatch,
            fake_engine,
            {**CFG, "size": 0, "block_count": 0, "block_total": 0, "blocks": [], "edges": []},
        )
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        payload = json_body(body, headers)
        # No diagram without an explanation: the route states why there is none.
        assert payload["blocks"] == []
        assert payload["edges"] == []
        assert isinstance(payload["note"], str) and payload["note"]

    def test_a_malformed_row_is_dropped(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(
            monkeypatch,
            fake_engine,
            {
                **CFG,
                "blocks": [
                    "nonsense",
                    {"va": "soon", "size": 1},
                    {"va": "0x1000", "size": "wide", "instruction_count": -3, "first": None},
                ],
                "edges": [
                    "nonsense",
                    {"from": "soon", "to": "0x1000"},
                    {"from": "0x1000", "to": "soon"},
                    {"from": "0x1000", "to": "0x100c"},
                ],
            },
        )
        ids = _seed(conn)
        _, headers, body = _get(ids["function"])
        payload = json_body(body, headers)
        assert payload["blocks"] == [
            {"va": 0x1000, "size": 0, "instruction_count": 0, "first": "", "last": ""}
        ]
        assert payload["edges"] == [{"from": 0x1000, "to": 0x100C, "back_edge": False}]
        assert payload["block_count"] == 1

    def test_the_engine_gets_the_function_va_and_size(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        calls: list[tuple[str, int, int]] = []
        _install(monkeypatch, fake_engine, CFG, calls)
        ids = _seed(conn)
        _get(ids["function"])
        assert calls == [(PROJECT_DIR, 0x1000, 32)]

    def test_the_graph_is_not_stored(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _install(monkeypatch, fake_engine, CFG)
        ids = _seed(conn)
        _get(ids["function"])
        # The graph is derived from the binary on every request, like the xrefs
        # and references views: no scan row and no cached listing is written.
        assert store.list_scans(conn, ids["analysis"]) == []
        assert store.get_disasm(conn, ids["function"]) is None


class TestErrors:
    def test_unknown_function_is_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = _get(999)
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_without_a_project_context_is_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, project=False)
        status, headers, body = _get(ids["function"])
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_without_an_engine_is_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = _seed(conn)
        status, headers, body = _get(ids["function"])
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_an_engine_failure_is_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew asm exited with code 2: x86 targets only")

        monkeypatch.setattr(fake_engine, "control_flow_graph", boom)
        ids = _seed(conn)
        status, headers, body = _get(ids["function"])
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "x86 targets only" in payload["detail"]

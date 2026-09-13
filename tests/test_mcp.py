"""Tests for the stdio MCP server and the tool registry."""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import anyio
import pytest
from conftest import FakeEngine
from graph_helpers import FUNCTION_NAME, node_id, seed_corpus
from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage
from typer.main import get_command
from typer.testing import CliRunner

from reportal import (
    __version__,
    cli,
    comments,
    components,
    data_types,
    engines,
    knowledge,
    llm,
    mcp_server,
    mcp_tools,
    pipeline,
    plugins,
    remote_ingest,
    store,
    threat,
)
from reportal.mcp_tools import Tool, ToolAnnotations

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_live_state() -> Iterator[None]:
    """Drop the process-wide live composition around each test."""
    pipeline.reset_live_state()
    yield
    pipeline.reset_live_state()


def _drop_action(payload: dict[str, Any]) -> dict[str, Any]:
    """Return *payload* without the journal action id a wired tool adds."""
    payload.pop("journal_action", None)
    return payload


# The tools reportal ships in-tree, split by annotation.  `search` reads the
# store and runs nothing, so it is read-only despite the capability list it
# belongs to; every other listed capability is mutating.
_READ_ONLY_TOOLS = frozenset(
    {
        "list_conversation_runs",
        "get_conversation_run",
        "get_indirect_call_sites",
        "get_function_capabilities",
        "get_function_strings",
        "list_analysis_strings",
        "list_function_edges",
        "get_functions_callees_callers",
        "get_function_matches",
        "get_signature_batch",
        "get_data_type_functions",
        "list_external_sources",
        "get_external_report",
        "get_external_status",
        "list_secrets",
        "list_models",
        "get_ai_decompilation",
        "get_ai_decompilation_status",
        "list_ai_decompilation_tokens",
        "get_ai_line_attributions",
        "list_ai_line_comments",
        "get_config",
        "list_collections",
        "get_collection",
        "list_binaries",
        "get_binary",
        "list_functions",
        "get_function",
        "get_fingerprint",
        "get_imports",
        "get_strings",
        "read_memory",
        "get_tags",
        "get_triage",
        "get_function_triage",
        "get_report",
        "get_pdf_status",
        "get_structs",
        "list_data_types",
        "get_data_type_history",
        "get_signature",
        "list_signatures",
        "get_signature_history",
        "get_crypto_scan",
        "get_pe_info",
        "get_die_info",
        "get_additional_details",
        "get_details_status",
        "get_filetype",
        "get_security_scan",
        "get_capabilities",
        "get_threat_report",
        "get_remediation",
        "get_secrets_scan",
        "get_protocols_scan",
        "get_behavior_scan",
        "get_hardening_scan",
        "get_unstrip",
        "get_matches",
        "get_lineage",
        "get_related_binaries",
        "get_composition",
        "list_families",
        "get_detect_scan",
        "diff_functions",
        "get_disasm",
        "get_decompilation",
        "get_xrefs",
        "get_history",
        "get_summary",
        "get_ai_comments",
        "list_comments",
        "get_type_suggestions",
        "get_renames",
        "list_conversations",
        "get_conversation",
        "get_pipeline",
        "list_components",
        "list_integrations",
        "get_auto_run",
        "list_documents",
        "search_knowledge",
        "retrieve_knowledge",
        "get_graph",
        "graph_neighbors",
        "list_graph_backends",
        "search",
        "get_analysis",
        "get_analysis_params",
        "get_analysis_func_maps",
        "get_imported_functions",
        "get_firmware_scan",
        "get_activity",
        "list_feedback",
        "get_sandbox_report",
        "get_sandbox_status",
        "list_users",
        "list_teams",
        "get_job",
        "list_journal",
        "list_jobs",
        "list_notifications",
    }
)

_DESTRUCTIVE_TOOLS = frozenset(
    {
        "run_conversation_agent",
        "confirm_conversation_run",
        "cancel_conversation_run",
        "add_function_string",
        "delete_function_string",
        "replace_analysis_strings",
        "add_function_edge",
        "delete_function_edge",
        "canonicalize_function_names",
        "copy_signature",
        "import_type_definitions",
        "run_external_source",
        "set_secret",
        "delete_secret",
        "upgrade_analysis_model",
        "run_ai_decompilation",
        "set_ai_decompilation_overrides",
        "rate_ai_decompilation",
        "add_ai_line_comment",
        "update_ai_line_comment",
        "delete_ai_line_comment",
        "update_analysis",
        "append_analysis_log",
        "requeue_analysis",
        "set_analysis_tags",
        "submit_job",
        "cancel_job",
        "run_jobs",
        "export_zipped_binary",
        "create_collection",
        "update_collection",
        "delete_collection",
        "set_collection_members",
        "set_collection_tags",
        "run_fingerprint",
        "rename_function",
        "revert_name",
        "apply_match",
        "run_match",
        "run_lineage",
        "run_related_binaries",
        "run_composition",
        "register_family",
        "delete_family",
        "run_detect",
        "run_triage",
        "run_function_triage",
        "run_report",
        "generate_pdf_report",
        "run_structs",
        "import_data_types",
        "edit_data_type",
        "export_data_types",
        "revert_data_type_history",
        "run_signature_import",
        "edit_signature",
        "export_signatures",
        "revert_signature_history",
        "run_crypto_scan",
        "run_pe_info",
        "run_filetype",
        "run_security_scan",
        "run_capabilities",
        "run_threat_report",
        "run_remediation",
        "run_secrets_scan",
        "run_protocols_scan",
        "run_behavior_scan",
        "run_hardening_scan",
        "run_unstrip",
        "build_graph",
        "sync_graph_backend",
        "apply_unstrip",
        "run_summary",
        "run_ai_comments",
        "run_type_suggestions",
        "suggest_renames",
        "apply_renames",
        "revert_renames",
        "create_conversation",
        "send_conversation_message",
        "delete_conversation",
        "run_pipeline",
        "revert_pipeline_run",
        "reload_components",
        "deactivate_components",
        "run_auto",
        "revert_auto_run",
        "recover_auto_run",
        "create_tag",
        "tag_binary",
        "untag_binary",
        "add_comment",
        "update_comment",
        "delete_comment",
        "bulk_binaries",
        "bulk_functions",
        "bulk_analyses",
        "add_user",
        "rotate_user_token",
        "update_user",
        "delete_user",
        "create_team",
        "delete_team",
        "add_team_member",
        "remove_team_member",
        "set_binary_scope",
        "set_collection_scope",
        "run_firmware_scan",
        "extract_firmware_regions",
        "add_feedback",
        "run_sandbox_detonation",
        "ingest_document",
        "ingest_url",
        "delete_document",
        "extract_archive",
        "revert_journal_entry",
    }
)

_EXPECTED_TOOLS = _READ_ONLY_TOOLS | _DESTRUCTIVE_TOOLS


class _EntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value


class _EntryPoints:
    """Minimal stand-in for the EntryPoints collection."""

    def __init__(self, entries: list[_EntryPoint]) -> None:
        self._entries = entries

    def select(self, *, group: str) -> list[_EntryPoint]:
        return list(self._entries)


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: _EntryPoint) -> None:
    monkeypatch.setattr(plugins, "entry_points", lambda: _EntryPoints(list(entries)))


@pytest.fixture(autouse=True)
def _isolate_tools() -> Iterator[None]:
    """Reload the tool registry around each test, whatever a test registered."""
    mcp_tools.refresh_tools()
    yield
    mcp_tools.refresh_tools()


def _seed_binary(conn: Any, tmp_path: Path, *, with_file: bool = True) -> dict[str, int]:
    """Create one binary, analysis and two named functions in the isolated DB."""
    path = tmp_path / "demo.exe"
    if with_file:
        path.write_bytes(b"MZ" + b"\x00" * 30)
    binary_id = store.add_binary(
        conn, sha256="ab" * 32, name="demo.exe", path=str(path), size=32, fmt="EXE"
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    first = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
    second = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16)
    return {"binary": binary_id, "analysis": analysis_id, "first": first, "second": second}


def _call(name: str, arguments: dict[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


# JSON-RPC 2.0 error codes, and the MCP revision these tests negotiate.
PROTOCOL_VERSION = "2025-06-18"
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


def _request(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """One JSON-RPC request."""
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _tools_call(request_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """One ``tools/call`` request."""
    return _request(request_id, "tools/call", {"name": name, "arguments": arguments})


def _initialize_params() -> dict[str, Any]:
    """The ``initialize`` params a client sends."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "reportal-tests", "version": "1"},
    }


def protocol(
    requests: list[dict[str, Any]], *, responses: int, handshake: bool = True
) -> list[dict[str, Any]]:
    """Run *requests* through the server and return exactly *responses* replies.

    The server is the real one, on anyio's in-memory streams: the SDK's
    transport loop, its dispatch and reportal's handlers.  The session opens
    with ``initialize`` unless *handshake* is false, because the protocol
    refuses a request made before it.  Waiting for an exact reply count is what
    makes "a notification produces no reply" testable without a timeout, and
    what keeps a missing reply from hanging the suite.
    """
    preamble = (
        [
            _request(0, "initialize", _initialize_params()),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
        if handshake
        else []
    )
    messages = preamble + requests
    expected = responses + (1 if handshake else 0)

    async def run() -> list[dict[str, Any]]:
        server = mcp_server.build_server()
        inbound_send, inbound_receive = anyio.create_memory_object_stream[Any](len(messages) + 8)
        outbound_send, outbound_receive = anyio.create_memory_object_stream[Any](len(messages) + 8)
        replies: list[dict[str, Any]] = []
        done = anyio.Event()

        async def collect() -> None:
            async for message in outbound_receive:
                replies.append(
                    json.loads(message.message.model_dump_json(by_alias=True, exclude_unset=True))
                )
                if len(replies) >= expected:
                    done.set()

        async with anyio.create_task_group() as group:
            group.start_soon(
                server.run,
                inbound_receive,
                outbound_send,
                server.create_initialization_options(),
            )
            group.start_soon(collect)
            for message in messages:
                await inbound_send.send(
                    SessionMessage(types.jsonrpc_message_adapter.validate_python(message))
                )
            with anyio.fail_after(30):
                await done.wait()
            group.cancel_scope.cancel()
        return replies[1:] if handshake else replies

    return anyio.run(run)


def _boom(arguments: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError("handler exploded")


def _noop(arguments: dict[str, Any]) -> dict[str, Any]:
    return {}


def _tool(name: str) -> Tool:
    return Tool(
        name=name,
        description="A test tool.",
        input_schema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
        handler=_noop,
    )


class TestRegistry:
    def test_builtin_tools_cover_every_capability(self) -> None:
        names = {tool.name for tool in mcp_tools.tools()}
        assert names == _EXPECTED_TOOLS
        assert len(names) == 219
        assert len(_READ_ONLY_TOOLS) == 102
        assert len(_DESTRUCTIVE_TOOLS) == 117

    def test_every_tool_is_well_formed(self) -> None:
        for tool in mcp_tools.tools():
            assert tool.name
            assert tool.name == tool.name.strip().lower()
            assert tool.description.strip()
            assert tool.input_schema["type"] == "object"
            assert isinstance(tool.input_schema.get("properties", {}), dict)
            assert callable(tool.handler)

    def test_annotations_match_the_read_write_split(self) -> None:
        for tool in mcp_tools.tools():
            if tool.name in _READ_ONLY_TOOLS:
                assert tool.annotations.read_only_hint is True
                assert tool.annotations.destructive_hint is False
            else:
                assert tool.annotations.read_only_hint is False
                assert tool.annotations.destructive_hint is True

    def test_register_tool_adds_it(self) -> None:
        mcp_tools.register_tool(_tool("probe"), origin="test")
        assert "probe" in [tool.name for tool in mcp_tools.tools()]

    def test_duplicate_name_raises(self) -> None:
        mcp_tools.register_tool(_tool("probe"), origin="test")
        with pytest.raises(mcp_tools.RegistryError):
            mcp_tools.register_tool(_tool("probe"), origin="other")

    def test_registering_a_non_tool_raises(self) -> None:
        with pytest.raises(mcp_tools.RegistryError):
            mcp_tools.register_tool("nope")  # type: ignore[arg-type]

    def test_registering_an_empty_name_raises(self) -> None:
        with pytest.raises(mcp_tools.RegistryError):
            mcp_tools.register_tool(_tool(""), origin="test")

    def test_refresh_drops_a_registered_extra(self) -> None:
        mcp_tools.register_tool(_tool("probe"), origin="test")
        names = [tool.name for tool in mcp_tools.refresh_tools()]
        assert "probe" not in names
        assert "list_binaries" in names

    def test_entry_point_tool_is_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "mcp_plugins:PROBE_TOOL"))
        names = [tool.name for tool in mcp_tools.refresh_tools()]
        assert "probe" in names

    def test_entry_point_factory_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("made", "mcp_plugins:make_tool"))
        names = [tool.name for tool in mcp_tools.refresh_tools()]
        assert "factory-made" in names

    def test_entry_point_without_a_module_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_entry_point_with_an_unimportable_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin:thing"))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_entry_point_with_a_missing_attribute_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "mcp_plugins:absent_attr"))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_entry_point_that_is_not_a_tool_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "mcp_plugins:NOT_A_TOOL"))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_entry_point_with_a_broken_factory_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "mcp_plugins:broken_factory"))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_entry_point_returning_the_wrong_type_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "mcp_plugins:returns_wrong_type"))
        assert "list_binaries" in [tool.name for tool in mcp_tools.refresh_tools()]

    def test_a_broken_registration_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin:thing"))
        with caplog.at_level("WARNING"):
            mcp_tools.refresh_tools()
        assert "skipping broken reportal.mcp_tools registration" in caplog.text

    def test_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("dup", "mcp_plugins:DUPLICATE_LIST_BINARIES"))
        with pytest.raises(mcp_tools.RegistryError):
            mcp_tools.refresh_tools()


class TestProtocol:
    """The wire behaviour, over the SDK's own transport.

    The server runs on anyio's in-memory streams, so these tests speak real
    JSON-RPC -- the SDK's framing, ``initialize`` and dispatch -- with no
    process and no sleep.  :func:`protocol` waits for an exact number of
    replies, so a test that expects one that never comes fails there instead of
    hanging.
    """

    def test_initialize_response_shape(self) -> None:
        (reply,) = protocol(
            [_request(1, "initialize", _initialize_params())], responses=1, handshake=False
        )
        result = reply["result"]
        assert result["protocolVersion"] == PROTOCOL_VERSION
        assert result["serverInfo"] == {
            "name": "reportal",
            "title": "reportal",
            "version": __version__,
        }
        assert result["capabilities"]["tools"] == {"listChanged": False}

    def test_the_initialized_notification_has_no_reply(self) -> None:
        replies = protocol(
            [
                _request(1, "initialize", _initialize_params()),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                _request(2, "ping"),
            ],
            responses=2,
            handshake=False,
        )
        assert [reply["id"] for reply in replies] == [1, 2]

    def test_an_unknown_notification_has_no_reply(self) -> None:
        replies = protocol(
            [
                {"jsonrpc": "2.0", "method": "notifications/nothing"},
                _request(2, "ping"),
            ],
            responses=1,
        )
        assert [reply["id"] for reply in replies] == [2]

    def test_ping_is_answered(self) -> None:
        (reply,) = protocol([_request(1, "ping")], responses=1)
        assert reply["result"] == {}

    def test_tools_list_describes_every_tool(self) -> None:
        (reply,) = protocol([_request(2, "tools/list")], responses=1)
        descriptors = reply["result"]["tools"]
        assert len(descriptors) == len(mcp_tools.tools())
        for descriptor in descriptors:
            assert descriptor["name"]
            assert descriptor["description"]
            assert descriptor["inputSchema"]["type"] == "object"
            annotations = descriptor["annotations"]
            assert {"readOnlyHint", "destructiveHint"} <= set(annotations)
            assert isinstance(annotations["readOnlyHint"], bool)
            assert isinstance(annotations["destructiveHint"], bool)

    def test_tools_call_returns_the_result_payload(self) -> None:
        (reply,) = protocol([_tools_call(3, "list_integrations", {})], responses=1)
        result = reply["result"]
        assert result["isError"] is False
        payload = json.loads(result["content"][0]["text"])
        assert payload["count"] == len(payload["seams"])

    def test_unknown_method_is_a_jsonrpc_error(self) -> None:
        (reply,) = protocol([_request(4, "nope")], responses=1)
        assert reply["error"]["code"] == METHOD_NOT_FOUND

    def test_unknown_tool_is_invalid_params(self) -> None:
        (reply,) = protocol([_tools_call(5, "nope", {})], responses=1)
        assert reply["error"]["code"] == INVALID_PARAMS

    def test_missing_tool_name_is_invalid_params(self) -> None:
        (reply,) = protocol([_request(6, "tools/call", {})], responses=1)
        assert reply["error"]["code"] == INVALID_PARAMS

    def test_missing_required_argument_is_invalid_params(self) -> None:
        (reply,) = protocol([_tools_call(7, "get_binary", {})], responses=1)
        assert reply["error"]["code"] == INVALID_PARAMS

    def test_handler_exception_is_a_tool_error_and_the_session_survives(self) -> None:
        mcp_tools.register_tool(
            Tool(
                name="boom",
                description="Boom.",
                input_schema={"type": "object", "properties": {}},
                annotations=ToolAnnotations(False, True),
                handler=_boom,
            ),
            origin="test",
        )
        replies = protocol(
            [_tools_call(8, "boom", {}), _request(9, "ping")],
            responses=2,
        )
        result = replies[0]["result"]
        assert result["isError"] is True
        assert json.loads(result["content"][0]["text"])["error"] == "internal-error"
        assert replies[1]["result"] == {}


class TestReadTools:
    def test_list_binaries_and_get_binary(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("list_binaries")
        assert is_error is False
        assert [binary["id"] for binary in payload["binaries"]] == [ids["binary"]]

        payload, is_error = _call("get_binary", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["name"] == "demo.exe"

    def test_get_binary_missing_is_a_structured_error(self, conn: Any) -> None:
        payload, is_error = _call("get_binary", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_list_functions_and_get_function(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("list_functions", {"binary_id": ids["binary"]})
        assert is_error is False
        assert [function["va"] for function in payload["functions"]] == [0x1000, 0x2000]

        payload, is_error = _call("get_function", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["name"] == "sub_1000"

    def test_get_tags_lists_all_then_binary_scoped(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        store.create_tag(conn, "malware")
        store.add_binary_tag(conn, ids["binary"], store.create_tag(conn, "pe"))
        payload, is_error = _call("get_tags")
        assert is_error is False
        assert {tag["name"] for tag in payload["tags"]} == {"malware", "pe"}

        payload, is_error = _call("get_tags", {"binary_id": ids["binary"]})
        assert is_error is False
        assert [tag["name"] for tag in payload["tags"]] == ["pe"]

    def test_get_triage_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_triage", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_triage" in payload["detail"]

    def test_get_summary_without_an_artifact_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_summary", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "no-artifact"

    def test_get_threat_report_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_threat_report", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_threat_report" in payload["detail"]

    def test_get_remediation_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_remediation", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_remediation" in payload["detail"]

    def test_get_pe_info_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_pe_info", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_pe_info" in payload["detail"]

    def test_get_secrets_scan_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_secrets_scan", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_secrets_scan" in payload["detail"]

    def test_get_filetype_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_filetype", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_filetype" in payload["detail"]

    def test_get_behavior_scan_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "get_behavior_scan", {"binary_id": ids["binary"], "domain": "execution"}
        )
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_behavior_scan" in payload["detail"]

    def test_get_behavior_scan_without_a_domain_reports_nulls(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_behavior_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload == {"execution": None, "networking": None, "filesystem": None}

    def test_get_hardening_scan_without_a_scan_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "get_hardening_scan", {"binary_id": ids["binary"], "domain": "obfuscation"}
        )
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_hardening_scan" in payload["detail"]

    def test_get_hardening_scan_without_a_domain_reports_nulls(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_hardening_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload == {"anti-analysis": None, "obfuscation": None}

    def test_get_disasm_uses_the_rebrew_context(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        store.set_rebrew_context(conn, ids["binary"], str(tmp_path))
        payload, is_error = _call("get_disasm", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["format"] == "nasm"
        assert payload["va"] == 0x1000
        assert "func_1000" in payload["disasm"]

    def test_diff_functions_returns_the_alignment(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        store.set_rebrew_context(conn, ids["binary"], str(tmp_path))
        store.record_match(
            conn,
            function_id=ids["first"],
            candidate_function_id=ids["second"],
            similarity=64.0,
            confidence=0.5,
        )
        store.set_decompilation(conn, ids["first"], "void a(void)\n{\n  return;\n}\n", "kuna")
        store.set_decompilation(conn, ids["second"], "void b(void)\n{\n  int x;\n}\n", "kuna")
        payload, is_error = _call(
            "diff_functions",
            {"function_id": ids["first"], "candidate_function_id": ids["second"]},
        )
        assert is_error is False
        assert payload["kind"] == "decomp"
        assert payload["similarity"] == 64.0
        assert payload["summary"]["delete"] > 0
        assert payload["entries"]

    def test_diff_functions_unknown_candidate_is_a_structured_error(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "diff_functions", {"function_id": ids["first"], "candidate_function_id": 999}
        )
        assert is_error is True
        assert payload["error"] == "candidate not found"

    def test_diff_functions_invalid_kind_is_a_structured_error(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "diff_functions",
            {
                "function_id": ids["first"],
                "candidate_function_id": ids["second"],
                "kind": "bytes",
            },
        )
        assert is_error is True
        assert payload["error"] == "invalid kind"

    def test_search_returns_grouped_rows(self, conn: Any, tmp_path: Path) -> None:
        _seed_binary(conn, tmp_path)
        payload, is_error = _call("search", {"query": "sub_"})
        assert is_error is False
        assert [function["name"] for function in payload["functions"]] == ["sub_1000", "sub_2000"]

    def test_search_can_be_typed_to_binaries(self, conn: Any, tmp_path: Path) -> None:
        _seed_binary(conn, tmp_path)
        payload, is_error = _call("search", {"query": "demo", "kind": "binary"})
        assert is_error is False
        assert [binary["name"] for binary in payload["binaries"]] == ["demo.exe"]
        assert payload["functions"] == []

    def test_search_refuses_an_ambiguous_hash(self, conn: Any) -> None:
        store.add_binary(conn, sha256="ab" * 32, name="one.bin")
        store.add_binary(conn, sha256="ab" * 31 + "cd", name="two.bin")
        payload, is_error = _call("search", {"query": "abababab", "kind": "sha256"})
        assert is_error is True
        assert payload["error"] == "ambiguous-hash"

    def test_search_rejects_an_unknown_kind(self, conn: Any) -> None:
        payload, is_error = _call("search", {"query": "x", "kind": "nonsense"})
        assert is_error is True
        assert payload["error"] == "invalid-kind"

    def test_create_and_get_conversation(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "create_conversation", {"scope_kind": "function", "scope_id": ids["first"]}
        )
        assert is_error is False
        conversation_id = payload["id"]

        payload, is_error = _call("get_conversation", {"conversation_id": conversation_id})
        assert is_error is False
        assert payload["messages"] == []
        assert payload["scope_kind"] == "function"

    def test_list_conversations_filters_by_scope(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _call("create_conversation", {"scope_kind": "function", "scope_id": ids["first"]})
        payload, is_error = _call(
            "list_conversations", {"scope_kind": "function", "scope_id": ids["first"]}
        )
        assert is_error is False
        assert len(payload["conversations"]) == 1


class TestDestructiveTools:
    def test_extract_archive_registers_members(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        source = tmp_path / "bundle.zip"
        with zipfile.ZipFile(source, "w") as zf:
            zf.writestr("member.bin", b"member bytes")
        binary_id = store.add_binary(
            conn,
            sha256="ef" * 32,
            name="bundle.zip",
            path=str(source),
            size=source.stat().st_size,
        )
        payload, is_error = _call("extract_archive", {"binary_id": binary_id})
        assert is_error is False
        assert payload["kept"] == 1
        assert payload["members"][0]["name"] == "member.bin"
        assert payload["collection_id"]
        assert len(store.list_binaries(conn)) == 2

    def test_extract_archive_refuses_an_external_format(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        source = tmp_path / "sample.rar"
        source.write_bytes(b"Rar!\x1a\x07\x00")
        binary_id = store.add_binary(
            conn, sha256="ee" * 32, name="sample.rar", path=str(source), size=4
        )
        payload, is_error = _call("extract_archive", {"binary_id": binary_id})
        assert is_error is True
        assert payload["error"] == "external-tool-required"

    def test_extract_archive_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("extract_archive", {"binary_id": 1234})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_rename_function_changes_the_store_and_history(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "rename_function", {"function_id": ids["first"], "name": "read_file"}
        )
        assert is_error is False
        assert payload["new_name"] == "read_file"
        assert cast(dict[str, Any], store.get_function(conn, ids["first"]))["name"] == "read_file"

        payload, is_error = _call("get_history", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["history"][0]["new_name"] == "read_file"

    def test_revert_name_restores_the_previous_name(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _call("rename_function", {"function_id": ids["first"], "name": "read_file"})
        history = store.list_name_history(conn, ids["first"])
        payload, is_error = _call(
            "revert_name", {"function_id": ids["first"], "history_id": history[0]["id"]}
        )
        assert is_error is False
        assert payload["name"] == "sub_1000"
        assert cast(dict[str, Any], store.get_function(conn, ids["first"]))["name"] == "sub_1000"

    def test_create_tag_and_tag_binary_change_the_store(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("create_tag", {"name": "malware"})
        assert is_error is False
        tag_id = payload["tag_id"]

        payload, is_error = _call("tag_binary", {"binary_id": ids["binary"], "tag_id": tag_id})
        assert is_error is False
        assert [tag["id"] for tag in store.get_binary_tags(conn, ids["binary"])] == [tag_id]

        payload, is_error = _call("untag_binary", {"binary_id": ids["binary"], "tag_id": tag_id})
        assert is_error is False
        assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_delete_conversation_removes_it(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        created, _ = _call(
            "create_conversation", {"scope_kind": "function", "scope_id": ids["first"]}
        )
        payload, is_error = _call("delete_conversation", {"conversation_id": created["id"]})
        assert is_error is False
        assert payload["deleted"] is True
        payload, is_error = _call("get_conversation", {"conversation_id": created["id"]})
        assert is_error is True
        assert payload["error"] == "conversation not found"

    def test_engine_dependent_tool_without_an_engine_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call("run_triage", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_triage_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_triage", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["meta"]["format"] == "pe"
        assert "analyze" in fake_engine.calls

        stored, _ = _call("get_triage", {"binary_id": ids["binary"]})
        assert stored["meta"]["format"] == "pe"

    def test_run_pe_info_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_pe_info", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["format"] == "pe"
        assert payload["flags_summary"] == ["SEH", "Isolation"]
        assert "pe_info" in fake_engine.calls

        stored, is_error = _call("get_pe_info", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["sections"] == payload["sections"]

    def test_run_pe_info_without_a_file_is_a_structured_error(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path, with_file=False)
        payload, is_error = _call("run_pe_info", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_run_capabilities_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_capabilities", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert "capabilities" in payload

        stored, is_error = _call("get_capabilities", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["count"] == payload["count"]

    def test_run_secrets_scan_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {"strings": [{"text": token, "va": "0x402000"}]},
        )
        payload, is_error = _call("run_secrets_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert payload["count"] == 1
        assert payload["findings"][0]["name"] == "github-token"

        stored, is_error = _call("get_secrets_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["count"] == payload["count"]

    def test_run_secrets_scan_without_an_engine(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call("run_secrets_scan", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_filetype_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        packed = {
            "format": "pe",
            "sections": [{"name": "UPX0"}, {"name": "UPX1", "execute": True}],
        }
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: dict(packed))
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {"strings": [{"text": "UPX!", "va": "0x402000"}]},
        )
        payload, is_error = _call("run_filetype", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert payload["matches"][0]["name"] == "UPX"

        stored, is_error = _call("get_filetype", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["count"] == payload["count"]

    def test_run_filetype_without_an_engine(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call("run_filetype", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_filetype_with_a_failing_engine_call(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(binary: str | Path) -> dict[str, Any]:
            raise engines.EngineError("rebrew pe-info failed: not a PE")

        for name in ("pe_info", "fingerprint", "imports", "strings"):
            monkeypatch.setattr(fake_engine, name, boom)
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_filetype", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-error"

    def test_run_threat_report_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_threat_report", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert set(payload["iocs"]) == set(threat.IOC_CATEGORIES)

        stored, is_error = _call("get_threat_report", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["binary_id"] == ids["binary"]

    def test_run_threat_report_without_an_engine_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call("run_threat_report", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_remediation_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {
                "strings": [{"text": "Distinctive marker text", "kind": "utf16", "va": 0x402000}]
            },
        )
        payload, is_error = _call("run_remediation", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert "rule demo_exe_" in payload["rule"]
        assert payload["string_count"] == 1

        stored, is_error = _call("get_remediation", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored["rule_name"] == payload["rule_name"]

    def test_run_remediation_without_an_engine_is_a_structured_error(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call("run_remediation", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_behavior_scan_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {
                "imports": [
                    {"dll": "KERNEL32.dll", "name": "CreateProcessA", "iat_va": "0x401000"}
                ],
                "stubs": [],
            },
        )
        payload, is_error = _call(
            "run_behavior_scan", {"binary_id": ids["binary"], "domain": "execution"}
        )
        assert is_error is False
        assert payload["domain"] == "execution"
        assert payload["count"] == 1

        stored, is_error = _call(
            "get_behavior_scan", {"binary_id": ids["binary"], "domain": "execution"}
        )
        assert is_error is False
        assert stored["count"] == 1

    def test_run_behavior_scan_without_a_domain_runs_all(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_behavior_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert set(_drop_action(payload)) == {"execution", "networking", "filesystem"}

        stored, is_error = _call("get_behavior_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert set(stored) == {"execution", "networking", "filesystem"}
        assert all(scan is not None for scan in stored.values())

    def test_run_behavior_scan_with_an_unknown_domain(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "run_behavior_scan", {"binary_id": ids["binary"], "domain": "registry"}
        )
        assert is_error is True
        assert payload["error"] == "invalid domain"

    def test_run_behavior_scan_without_an_engine(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call(
            "run_behavior_scan", {"binary_id": ids["binary"], "domain": "execution"}
        )
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_hardening_scan_with_a_fake_engine(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {
                "imports": [
                    {"dll": "KERNEL32.dll", "name": "IsDebuggerPresent", "iat_va": "0x401000"}
                ],
                "stubs": [],
            },
        )
        payload, is_error = _call(
            "run_hardening_scan", {"binary_id": ids["binary"], "domain": "anti-analysis"}
        )
        assert is_error is False
        assert payload["domain"] == "anti-analysis"
        assert payload["count"] == 1

        stored, is_error = _call(
            "get_hardening_scan", {"binary_id": ids["binary"], "domain": "anti-analysis"}
        )
        assert is_error is False
        assert stored["count"] == 1

    def test_run_hardening_scan_without_a_domain_runs_both(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_hardening_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert set(_drop_action(payload)) == {"anti-analysis", "obfuscation"}

        stored, is_error = _call("get_hardening_scan", {"binary_id": ids["binary"]})
        assert is_error is False
        assert set(stored) == {"anti-analysis", "obfuscation"}
        assert all(scan is not None for scan in stored.values())

    def test_run_hardening_scan_with_an_unknown_domain(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "run_hardening_scan", {"binary_id": ids["binary"], "domain": "packing"}
        )
        assert is_error is True
        assert payload["error"] == "invalid domain"

    def test_run_hardening_scan_without_an_engine(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call(
            "run_hardening_scan", {"binary_id": ids["binary"], "domain": "anti-analysis"}
        )
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_summary_without_an_llm_is_llm_unavailable(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.delenv(llm.ENDPOINT_ENV, raising=False)
        llm.set_client(llm.LlmClient(None))
        payload, is_error = _call("run_summary", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "llm-unavailable"


# A recovered definition the data-type tool tests seed; its size is 27 bytes.
TYPE_DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar gap_0000[0x17];\n\tint field_C;\n} PlayerInfo;\n"
)


def _seed_data_type(conn: Any, binary_id: int) -> int:
    parsed = data_types.parse_definition(TYPE_DEFINITION)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        source=data_types.SOURCE_SCAN,
    )


def _seed_structs_scan(conn: Any, analysis_id: int) -> None:
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_STRUCTS,
        {
            "decompiled": 1,
            "skipped": 0,
            "structs": [{"name": "PlayerInfo", "va": 0x1000, "definition": TYPE_DEFINITION}],
        },
    )


class TestDataTypeTools:
    def test_list_data_types_returns_the_model(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_data_type(conn, ids["binary"])
        payload, is_error = _call("list_data_types", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["count"] == 1
        assert payload["types"][0]["size"] == 0x17 + 4
        assert payload["types"][0]["members"][0]["offset"] == 0

    def test_import_data_types_seeds_from_the_stored_scan(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_structs_scan(conn, ids["analysis"])
        payload, is_error = _call("import_data_types", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["created"] == 1
        payload, is_error = _call("list_data_types", {"binary_id": ids["binary"]})
        assert payload["types"][0]["name"] == "PlayerInfo"

    def test_import_data_types_without_a_scan_is_an_error(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("import_data_types", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"

    def test_edit_data_type_renames_a_member_and_recomputes(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "member": {"name": "field_C", "new_type": "short"},
            },
        )
        assert is_error is False
        assert payload["members"][1]["type"] == "short"
        assert payload["size"] == 0x17 + 2

        payload, is_error = _call(
            "edit_data_type", {"data_type_id": data_type_id, "name": "Player"}
        )
        assert is_error is False
        assert payload["name"] == "Player"

    def test_edit_data_type_adds_removes_and_deletes(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "add_member": {"name": "flags", "type": "unsigned int"},
            },
        )
        assert is_error is False
        assert payload["size"] == 0x17 + 8

        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "remove_member": {"name": "flags"}},
        )
        assert is_error is False
        assert payload["size"] == 0x17 + 4

        payload, is_error = _call("edit_data_type", {"data_type_id": data_type_id, "delete": True})
        assert is_error is False
        assert payload["deleted"] is True
        payload, is_error = _call("list_data_types", {"binary_id": ids["binary"]})
        assert payload["count"] == 0

    def test_edit_data_type_rejects_two_operations(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "name": "Player", "delete": True},
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_export_data_types_writes_a_header(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_data_type(conn, ids["binary"])
        target = tmp_path / "out" / "types.h"
        payload, is_error = _call(
            "export_data_types", {"binary_id": ids["binary"], "path": str(target)}
        )
        assert is_error is False
        assert payload["types"] == 1
        assert "PlayerInfo" in target.read_text(encoding="utf-8")

        payload, is_error = _call(
            "export_data_types", {"binary_id": ids["binary"], "path": str(target)}
        )
        assert is_error is True
        assert payload["error"] == "export exists"


ENUM_DEFINITION = "typedef enum NPFlags_s {\n\tNP_FLAG_A = 0,\n\tNP_FLAG_B = 1\n} NPFlags;\n"


def _seed_enum_type(conn: Any, binary_id: int) -> int:
    parsed = data_types.parse_definition(ENUM_DEFINITION)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        kind=parsed["kind"],
        values=parsed["values"],
        source=data_types.SOURCE_SCAN,
    )


def _builtin_tool(name: str) -> Tool:
    return next(tool for tool in mcp_tools.builtin_tools() if tool.name == name)


class TestDataTypeToolSchema:
    def test_edit_data_type_carries_the_model_fields_with_real_types(self) -> None:
        schema = _builtin_tool("edit_data_type").input_schema
        properties = schema["properties"]
        assert schema["required"] == ["data_type_id"]
        assert properties["kind"]["type"] == "string"
        assert set(properties["kind"]["enum"]) == set(data_types.KNOWN_KINDS)
        assert properties["size"]["type"] == "integer"

        member = properties["member"]["properties"]
        assert member["new_bits"]["type"] == "integer"
        assert member["new_count"]["type"] == "integer"
        assert member["new_pointer"]["type"] == "boolean"

        addition = properties["add_member"]["properties"]
        assert addition["pointer"]["type"] == "boolean"
        assert addition["count"]["type"] == "integer"
        assert addition["bits"]["type"] == "integer"
        assert addition["index"]["type"] == "integer"
        assert addition["after"]["type"] == "string"
        assert properties["add_member"]["required"] == ["name", "type"]

        removal = properties["remove_member"]["properties"]
        assert removal["name"]["type"] == "string"
        assert removal["index"]["type"] == "integer"

        gap = properties["to_gap"]["properties"]
        assert gap["size"]["type"] == "integer"
        assert gap["name"]["type"] == "string"

        restore = properties["from_gap"]["properties"]
        assert restore["bits"]["type"] == "integer"
        assert restore["count"]["type"] == "integer"
        assert properties["from_gap"]["required"] == ["new_name", "new_type"]

        assert properties["add_value"]["properties"]["value"]["type"] == "string"
        assert properties["edit_value"]["properties"]["new_value"]["type"] == "string"

    def test_the_tool_stays_annotated_destructive(self) -> None:
        tool = _builtin_tool("edit_data_type")
        assert tool.annotations.read_only_hint is False
        assert tool.annotations.destructive_hint is True


class TestDataTypeEditOperations:
    def test_type_fields_are_one_operation(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "kind": "union",
                "namespace": "winnt::kernel",
                "size": 32,
            },
        )
        assert is_error is False
        assert payload["kind"] == "union"
        assert payload["namespace"] == "winnt::kernel"
        assert payload["size"] == 32
        assert payload["size_check"]["match"] is False

    def test_an_unknown_kind_is_an_invalid_kind_error(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type", {"data_type_id": data_type_id, "kind": "bitfield"}
        )
        assert is_error is True
        assert payload["error"] == "invalid kind"
        assert "struct" in payload["detail"]

    def test_a_member_carries_its_bits_and_position(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "add_member": {
                    "name": "flags",
                    "type": "unsigned int",
                    "bits": 3,
                    "index": 1,
                },
            },
        )
        assert is_error is False
        assert [m["name"] for m in payload["members"]] == ["gap_0000", "flags", "field_C"]
        assert payload["members"][1]["bits"] == 3

        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "add_member": {"name": "tail", "type": "char", "after": "field_C"},
            },
        )
        assert is_error is False
        assert payload["members"][-1]["name"] == "tail"

    def test_index_and_after_together_are_refused(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "add_member": {
                    "name": "flags",
                    "type": "int",
                    "index": 0,
                    "after": "gap_0000",
                },
            },
        )
        assert is_error is True
        assert payload["error"] == "invalid member"

    def test_to_gap_and_from_gap(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "to_gap": {"name": "field_C"}},
        )
        assert is_error is False
        assert payload["members"][1]["is_gap"] is True
        assert payload["members"][1]["name"] == "gap_0017"

        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "from_gap": {"name": "gap_0017", "new_name": "counter", "new_type": "int"},
            },
        )
        assert is_error is False
        assert payload["members"][1]["is_gap"] is False
        assert payload["members"][1]["name"] == "counter"

    def test_enum_values_add_edit_and_remove(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_enum_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "add_value": {"name": "NP_FLAG_C"}},
        )
        assert is_error is False
        assert payload["values"][-1] == {"name": "NP_FLAG_C", "value": 2, "hex": "0x2"}
        assert "auto-incremented" in payload["note"]

        payload, is_error = _call(
            "edit_data_type",
            {
                "data_type_id": data_type_id,
                "edit_value": {"name": "NP_FLAG_C", "new_value": "0x40"},
            },
        )
        assert is_error is False
        assert payload["values"][-1]["hex"] == "0x40"

        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "remove_value": {"name": "NP_FLAG_A"}},
        )
        assert is_error is False
        assert [value["name"] for value in payload["values"]] == ["NP_FLAG_B", "NP_FLAG_C"]

    def test_enum_value_refusals(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_enum_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "add_value": {"name": "NP_FLAG_A"}},
        )
        assert is_error is True
        assert payload["error"] == "duplicate member"

        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "edit_value": {"name": "NP_FLAG_A"}},
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_operations_stay_exclusive(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        data_type_id = _seed_data_type(conn, ids["binary"])
        payload, is_error = _call(
            "edit_data_type",
            {"data_type_id": data_type_id, "kind": "union", "delete": True},
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_list_data_types_carries_the_size_check(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_data_type(conn, ids["binary"])
        payload, is_error = _call("list_data_types", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["types"][0]["size_check"]["match"] is True
        assert payload["types"][0]["members"][0]["is_gap"] is True
        assert payload["types"][0]["as_c"]


# A decompiler listing the signature tool tests parse; it carries a pointer
# return, a named and an unnamed parameter.
SIGNATURE_CODE = "char *sub_1000(unsigned int a0, int) {\n  return 0;\n}\n"


def _seed_signature_source(conn: Any, ids: dict[str, int]) -> None:
    store.set_decompilation(conn, ids["first"], SIGNATURE_CODE, "kuna")


class TestSignatureTools:
    def test_run_signature_import_and_list(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        payload, is_error = _call("run_signature_import", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["created"] == 1

        payload, is_error = _call("list_signatures", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["count"] == 1
        assert payload["signatures"][0]["name"] == "sub_1000"

        payload, is_error = _call("get_signature", {"function_id": ids["first"]})
        assert is_error is False
        assert payload["return_type"] == "char *"
        assert payload["parameters"][0]["type"] == "unsigned int"
        assert payload["parameters"][1]["name"] == ""

    def test_get_signature_without_one_is_an_error(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_signature", {"function_id": ids["first"]})
        assert is_error is True
        assert payload["error"] == "signature not found"

    def test_edit_signature_head_and_parameters(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        _call("run_signature_import", {"binary_id": ids["binary"]})

        payload, is_error = _call(
            "edit_signature", {"function_id": ids["first"], "return_type": "int"}
        )
        assert is_error is False
        assert payload["return_type"] == "int"

        payload, is_error = _call(
            "edit_signature", {"function_id": ids["first"], "calling_convention": "stdcall"}
        )
        assert is_error is False
        assert payload["calling_convention"] == "stdcall"

        payload, is_error = _call(
            "edit_signature",
            {
                "function_id": ids["first"],
                "parameter": {"index": 1, "name": "count"},
            },
        )
        assert is_error is False
        assert payload["parameters"][1]["name"] == "count"

        payload, is_error = _call(
            "edit_signature",
            {
                "function_id": ids["first"],
                "add_parameter": {"type": "char *", "name": "buffer"},
            },
        )
        assert is_error is False
        assert [p["name"] for p in payload["parameters"]] == ["a0", "count", "buffer"]

        payload, is_error = _call(
            "edit_signature", {"function_id": ids["first"], "remove_parameter": 0}
        )
        assert is_error is False
        assert [p["index"] for p in payload["parameters"]] == [0, 1]

        payload, is_error = _call("edit_signature", {"function_id": ids["first"], "delete": True})
        assert is_error is False
        assert payload["deleted"] is True

    def test_edit_signature_rejects_two_operations(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        _call("run_signature_import", {"binary_id": ids["binary"]})
        payload, is_error = _call(
            "edit_signature",
            {"function_id": ids["first"], "return_type": "int", "delete": True},
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_edit_signature_parameter_fields_and_move(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        _call("run_signature_import", {"binary_id": ids["binary"]})

        payload, is_error = _call(
            "edit_signature",
            {
                "function_id": ids["first"],
                "parameter": {"index": 0, "at": "ecx", "kind": "pointer", "bits": 32},
            },
        )
        assert is_error is False
        parameter = payload["parameters"][0]
        assert (parameter["at"], parameter["kind"], parameter["bits"]) == ("ecx", "pointer", 32)

        payload, is_error = _call(
            "edit_signature",
            {
                "function_id": ids["first"],
                "add_parameter": {"type": "int", "name": "count", "kind": "value"},
            },
        )
        assert is_error is False
        assert payload["parameters"][-1]["kind"] == "value"

        payload, is_error = _call(
            "edit_signature",
            {"function_id": ids["first"], "move_parameter": {"index": 0, "to_index": 1}},
        )
        assert is_error is False
        # The parameter that was first now sits second, still with contiguous
        # indices.
        assert payload["parameters"][1]["name"] == "a0"
        assert [p["index"] for p in payload["parameters"]] == [0, 1, 2]

    def test_edit_signature_rejects_a_bad_field(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        _call("run_signature_import", {"binary_id": ids["binary"]})
        payload, is_error = _call(
            "edit_signature",
            {"function_id": ids["first"], "parameter": {"index": 0, "bits": "wide"}},
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_export_signatures_writes_and_refuses(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        _seed_signature_source(conn, ids)
        _call("run_signature_import", {"binary_id": ids["binary"]})
        target = tmp_path / "out" / "prototypes.h"
        payload, is_error = _call(
            "export_signatures", {"binary_id": ids["binary"], "path": str(target)}
        )
        assert is_error is False
        assert payload["signatures"] == 1
        assert "sub_1000" in target.read_text(encoding="utf-8")

        payload, is_error = _call(
            "export_signatures", {"binary_id": ids["binary"], "path": str(target)}
        )
        assert is_error is True
        assert payload["error"] == "export exists"


# Note text the knowledge tool tests ingest; the query term appears in it and
# nowhere else in their corpus.
KNOWLEDGE_NOTE = "The widget retry counter lives in the timer callback.\n"


def _canned_fetch(
    url: str, *, allow_loopback: bool = False, max_bytes: int, timeout: float
) -> dict[str, Any]:
    """A ``remote_ingest.fetch`` stand-in, so the MCP test never reaches the network."""
    data = KNOWLEDGE_NOTE.encode()
    return {
        "url": url,
        "final_url": url,
        "content_type": "text/markdown",
        "data": data,
        "bytes": len(data),
    }


class TestKnowledgeTools:
    def test_ingest_then_list_and_search(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "ingest_document",
            {
                "scope_kind": "binary",
                "scope_id": ids["binary"],
                "title": "notes",
                "source": "notes.md",
                "text": KNOWLEDGE_NOTE,
            },
        )
        assert is_error is False
        assert payload["title"] == "notes"
        assert payload["duplicate"] is False
        assert payload["chunk_count"] == 1

        payload, is_error = _call(
            "list_documents", {"scope_kind": "binary", "scope_id": ids["binary"]}
        )
        assert is_error is False
        assert [document["title"] for document in payload["documents"]] == ["notes"]

        payload, is_error = _call("search_knowledge", {"query": "retry counter"})
        assert is_error is False
        assert payload["count"] == 1
        assert payload["results"][0]["title"] == "notes"
        assert payload["results"][0]["method"] == knowledge.METHOD_TFIDF

    def test_ingest_is_deduped_by_content(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        arguments = {
            "scope_kind": "binary",
            "scope_id": ids["binary"],
            "text": KNOWLEDGE_NOTE,
        }
        first, _ = _call("ingest_document", arguments)
        second, is_error = _call("ingest_document", arguments)
        assert is_error is False
        assert second["duplicate"] is True
        assert second["id"] == first["id"]

    def test_ingest_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call(
            "ingest_document", {"scope_kind": "binary", "scope_id": 999, "text": KNOWLEDGE_NOTE}
        )
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_ingest_rejects_an_invalid_scope_kind(self, conn: Any) -> None:
        payload, is_error = _call(
            "ingest_document", {"scope_kind": "collection", "scope_id": 1, "text": KNOWLEDGE_NOTE}
        )
        assert is_error is True
        assert payload["error"] == knowledge.ERROR_INVALID_SCOPE

    def test_ingest_rejects_blank_text(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "ingest_document",
            {"scope_kind": "binary", "scope_id": ids["binary"], "text": "   "},
        )
        assert is_error is True
        assert payload["error"] == knowledge.ERROR_EMPTY_TEXT

    def test_delete_document_removes_it(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        created, _ = _call(
            "ingest_document",
            {"scope_kind": "binary", "scope_id": ids["binary"], "text": KNOWLEDGE_NOTE},
        )
        payload, is_error = _call("delete_document", {"document_id": created["id"]})
        assert is_error is False
        assert payload["deleted"] is True
        assert store.list_chunks(conn, created["id"]) == []

    def test_delete_of_an_unknown_document_is_a_structured_error(self, conn: Any) -> None:
        payload, is_error = _call("delete_document", {"document_id": 4242})
        assert is_error is True
        assert payload["error"] == "document not found"

    def test_search_rejects_a_non_positive_limit(self, conn: Any) -> None:
        payload, is_error = _call("search_knowledge", {"query": "x", "limit": 0})
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_list_documents_rejects_an_invalid_scope_kind(self, conn: Any) -> None:
        payload, is_error = _call("list_documents", {"scope_kind": "team"})
        assert is_error is True
        assert payload["error"] == "invalid scope kind"

    def test_ingest_url_is_disabled_by_default(
        self, conn: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        payload, is_error = _call(
            "ingest_url",
            {"scope_kind": "project", "scope_id": 0, "url": "http://example.com/notes.md"},
        )
        assert is_error is True
        assert payload["error"] == remote_ingest.ERROR_DISABLED

    def test_ingest_url_requires_a_url(self, conn: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")
        with pytest.raises(MCPError) as excinfo:
            _call("ingest_url", {"scope_kind": "project", "scope_id": 0})
        assert excinfo.value.error.code == INVALID_PARAMS

    def test_ingest_url_stores_a_fetched_document(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")
        monkeypatch.setattr(
            remote_ingest, "validate_target", lambda url, **kwargs: (url, "127.0.0.1")
        )
        monkeypatch.setattr(remote_ingest, "fetch", _canned_fetch)
        payload, is_error = _call(
            "ingest_url",
            {"scope_kind": "binary", "scope_id": ids["binary"], "url": "http://example.com/n.md"},
        )
        assert is_error is False
        assert payload["title"] == "untitled"
        assert payload["source"] == "http://example.com/n.md"
        assert payload["chunk_count"] == 1
        listed, _ = _call("list_documents", {"scope_kind": "binary", "scope_id": ids["binary"]})
        assert [document["title"] for document in listed["documents"]] == ["untitled"]

    def test_ingest_url_rejects_a_redirect_to_a_blocked_target(
        self, conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")
        payload, is_error = _call(
            "ingest_url",
            {"scope_kind": "binary", "scope_id": ids["binary"], "url": "http://10.0.0.1/n.md"},
        )
        assert is_error is True
        assert payload["error"] == remote_ingest.ERROR_BLOCKED_TARGET


class TestGraphTools:
    def test_build_then_read_and_walk(self, conn: Any) -> None:
        ids = seed_corpus(conn)
        payload, is_error = _call("build_graph", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["nodes"] > 0
        assert payload["edges"] > 0

        payload, is_error = _call("get_graph", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["counts"]["function"] == 2
        assert payload["counts"]["document"] == 0

        target = node_id(ids["binary"], "function", ids["first"])
        payload, is_error = _call("graph_neighbors", {"node_id": target})
        assert is_error is False
        assert payload["node"]["label"] == FUNCTION_NAME
        assert set(payload["incoming"]) == {"contains", "mentions"}

    def test_get_graph_includes_documents_on_request(self, conn: Any) -> None:
        ids = seed_corpus(conn)
        _call("build_graph", {"binary_id": ids["binary"]})
        payload, is_error = _call(
            "get_graph", {"binary_id": ids["binary"], "include_documents": True}
        )
        assert is_error is False
        assert payload["counts"]["document"] == 1

    def test_get_graph_before_a_build_is_no_graph(self, conn: Any) -> None:
        ids = seed_corpus(conn)
        payload, is_error = _call("get_graph", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-graph"

    def test_get_graph_rejects_an_unknown_kind(self, conn: Any) -> None:
        ids = seed_corpus(conn)
        payload, is_error = _call("get_graph", {"binary_id": ids["binary"], "kind": "widget"})
        assert is_error is True
        assert payload["error"] == "invalid kind"

    def test_get_graph_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("get_graph", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_graph_neighbors_rejects_an_unknown_node(self, conn: Any) -> None:
        payload, is_error = _call("graph_neighbors", {"node_id": "b1:function:999"})
        assert is_error is True
        assert payload["error"] == "node not found"

    def test_build_graph_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("build_graph", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"


class TestFamilyTools:
    def test_list_families_is_empty_at_first(self, conn: Any) -> None:
        payload, is_error = _call("list_families")
        assert is_error is False
        assert payload == {"families": []}

    def test_get_detect_scan_before_a_run_is_no_scan(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_detect_scan", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"

    def test_register_run_and_read_back(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        reference = _seed_binary(conn, tmp_path)
        family, is_error = _call(
            "register_family",
            {
                "name": "DemoFamily",
                "reference_binary_id": reference["binary"],
                "aliases": ["DEMO.A"],
            },
        )
        assert is_error is False
        assert family["name"] == "DemoFamily"
        assert family["aliases"] == ["DEMO.A"]
        assert family["signatures"]["import_hash"]

        listed, is_error = _call("list_families")
        assert is_error is False
        assert [row["family_id"] for row in listed["families"]] == [family["family_id"]]

        detection, is_error = _call("run_detect", {"binary_id": reference["binary"]})
        assert is_error is False
        assert detection["count"] == 1
        assert detection["matches"][0]["name"] == "DemoFamily"
        assert detection["matches"][0]["signals"][0]["kind"] == "exact-binary"

        stored, is_error = _call("get_detect_scan", {"binary_id": reference["binary"]})
        assert is_error is False
        assert stored == _drop_action(detection)

    def test_register_family_rejects_a_blank_name(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "register_family", {"name": " ", "reference_binary_id": ids["binary"]}
        )
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_register_family_rejects_an_unknown_binary(
        self, conn: Any, fake_engine: FakeEngine
    ) -> None:
        payload, is_error = _call("register_family", {"name": "Demo", "reference_binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_register_family_without_an_engine_is_engine_unavailable(
        self, conn: Any, tmp_path: Path
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload, is_error = _call(
            "register_family", {"name": "Demo", "reference_binary_id": ids["binary"]}
        )
        assert is_error is True
        assert payload["error"] == "engine-unavailable"

    def test_run_detect_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("run_detect", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_delete_family_removes_it(
        self, conn: Any, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_binary(conn, tmp_path)
        family, _ = _call("register_family", {"name": "Demo", "reference_binary_id": ids["binary"]})
        payload, is_error = _call("delete_family", {"family_id": family["family_id"]})
        assert is_error is False
        assert _drop_action(payload) == {"family_id": family["family_id"], "deleted": True}
        listed, _ = _call("list_families")
        assert listed == {"families": []}

    def test_delete_family_rejects_an_unknown_id(self, conn: Any) -> None:
        payload, is_error = _call("delete_family", {"family_id": 404})
        assert is_error is True
        assert payload["error"] == "family not found"


def _seed_related_pair(conn: Any, tmp_path: Path) -> dict[str, int]:
    """Create two on-disk binaries whose stored fingerprints share every hash."""
    target_path = tmp_path / "target.exe"
    target_path.write_bytes(b"MZ" + b"\x00" * 30)
    other_path = tmp_path / "other.exe"
    other_path.write_bytes(b"MZ" + b"\x00" * 30)
    target = store.add_binary(
        conn, sha256="aa" * 32, name="target.exe", path=str(target_path), size=32, fmt="EXE"
    )
    other = store.add_binary(
        conn, sha256="bb" * 32, name="other.exe", path=str(other_path), size=32, fmt="EXE"
    )
    fingerprint = {"sha256": "aa" * 32, "imphash": "11" * 16, "rich_header_hash": "22" * 8}
    store.set_fingerprint(conn, target, dict(fingerprint))
    store.set_fingerprint(conn, other, dict(fingerprint))
    return {"target": target, "other": other}


class TestRelatedTools:
    def test_get_before_a_run_is_no_scan(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_related_binaries", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"

    def test_run_and_read_back(self, conn: Any, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = _seed_related_pair(conn, tmp_path)
        payload, is_error = _call("run_related_binaries", {"binary_id": ids["target"]})
        assert is_error is False
        assert payload["count"] == 1
        assert payload["candidates_considered"] == 1
        assert payload["related"][0]["binary_id"] == ids["other"]
        assert payload["related"][0]["classification"] == "identical"
        stored, is_error = _call("get_related_binaries", {"binary_id": ids["target"]})
        assert is_error is False
        assert stored == _drop_action(payload)

    def test_run_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("run_related_binaries", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_run_rejects_a_bad_limit(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_related_pair(conn, tmp_path)
        payload, is_error = _call("run_related_binaries", {"binary_id": ids["target"], "limit": 0})
        assert is_error is True
        assert payload["error"] == "invalid params"


class TestCompositionTools:
    def test_get_before_a_run_is_no_scan(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("get_composition", {"binary_id": ids["binary"]})
        assert is_error is True
        assert payload["error"] == "no-scan"

    def test_run_and_read_back(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call("run_composition", {"binary_id": ids["binary"]})
        assert is_error is False
        assert payload["binary_id"] == ids["binary"]
        assert payload["total_functions"] == 2
        assert payload["refined"] is False
        stored, is_error = _call("get_composition", {"binary_id": ids["binary"]})
        assert is_error is False
        assert stored == _drop_action(payload)

    def test_run_rejects_an_unknown_binary(self, conn: Any) -> None:
        payload, is_error = _call("run_composition", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"


class TestCommentAndBulkTools:
    def test_list_comments_is_empty_at_first(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "list_comments", {"scope_kind": "binary", "scope_id": ids["binary"]}
        )
        assert is_error is False
        assert payload == {"comments": []}

    def test_comment_lifecycle(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        created, is_error = _call(
            "add_comment",
            {"scope_kind": "function", "scope_id": ids["first"], "body": "look here"},
        )
        assert is_error is False
        assert created["author"] == comments.DEFAULT_AUTHOR

        listed, _ = _call("list_comments", {"scope_kind": "function", "scope_id": ids["first"]})
        assert [row["body"] for row in listed["comments"]] == ["look here"]

        updated, is_error = _call("update_comment", {"comment_id": created["id"], "body": "edited"})
        assert is_error is False
        assert updated["body"] == "edited"

        deleted, is_error = _call("delete_comment", {"comment_id": created["id"]})
        assert is_error is False
        assert deleted["deleted"] is True
        listed, _ = _call("list_comments", {"scope_kind": "function", "scope_id": ids["first"]})
        assert listed == {"comments": []}

    def test_add_comment_names_the_author(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "add_comment",
            {
                "scope_kind": "binary",
                "scope_id": ids["binary"],
                "body": "note",
                "author": "alice",
            },
        )
        assert is_error is False
        assert payload["author"] == "alice"

    def test_blank_comment_body_is_an_error(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "add_comment", {"scope_kind": "binary", "scope_id": ids["binary"], "body": "  "}
        )
        assert is_error is True
        assert payload["error"] == "invalid comment"

    def test_unknown_comment_scope_is_an_error(self, conn: Any) -> None:
        payload, is_error = _call("list_comments", {"scope_kind": "binary", "scope_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_unknown_comment_id_is_an_error(self, conn: Any) -> None:
        payload, is_error = _call("delete_comment", {"comment_id": 999})
        assert is_error is True
        assert payload["error"] == "comment not found"

    def test_bulk_binaries_tags_and_deletes(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        tagged, is_error = _call(
            "bulk_binaries",
            {"action": "add_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )
        assert is_error is False
        assert tagged["applied"] == 1
        tagged, _ = _call(
            "bulk_binaries",
            {"action": "remove_tag", "binary_ids": [ids["binary"]], "tag": "reviewed"},
        )
        assert tagged["applied"] == 1
        deleted, is_error = _call(
            "bulk_binaries", {"action": "delete", "binary_ids": [ids["binary"], 999]}
        )
        assert is_error is False
        assert deleted["applied"] == 1
        assert deleted["skipped"] == [{"id": 999, "reason": "not found"}]

    def test_bulk_binaries_rejects_an_unknown_action(self, conn: Any) -> None:
        payload, is_error = _call("bulk_binaries", {"action": "explode", "binary_ids": [1]})
        assert is_error is True
        assert payload["error"] == "invalid bulk request"

    def test_bulk_functions_renames_and_records_history(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "bulk_functions",
            {"action": "rename", "function_ids": [ids["first"]], "prefix": "NP_"},
        )
        assert is_error is False
        assert payload["applied"] == 1
        history, _ = _call("get_history", {"function_id": ids["first"]})
        assert history["history"][0]["source"] == "bulk-prefix"

    def test_bulk_functions_replaces_the_prefix(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        payload, is_error = _call(
            "bulk_functions",
            {
                "action": "rename",
                "function_ids": [ids["first"]],
                "prefix": "NP_",
                "replace": True,
            },
        )
        assert is_error is False
        assert payload["applied"] == 1

    def test_bulk_analyses_tags_and_deletes(self, portal_db: Path, conn: Any) -> None:
        binary_id = store.add_binary(conn, sha256="9" * 64, name="bulk.exe", path="/tmp/bulk.exe")
        first = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        second = store.create_analysis(conn, binary_id=binary_id, engine="rebrew")
        tagged, is_error = _call(
            "bulk_analyses",
            {"action": "add_tag", "analysis_ids": [first], "tag": "reviewed"},
        )
        assert is_error is False
        assert tagged["applied"] == 1
        assert [tag["name"] for tag in store.get_binary_tags(conn, binary_id)] == ["reviewed"]

        deleted, is_error = _call(
            "bulk_analyses", {"action": "delete", "analysis_ids": [first, 999]}
        )

        assert is_error is False
        assert deleted["applied"] == 1
        assert deleted["skipped"] == [{"id": 999, "reason": "not found"}]
        assert store.get_analysis(conn, first) is None
        assert store.get_analysis(conn, second) is not None

    def test_bulk_analyses_skips_a_lone_analysis_with_functions(
        self, portal_db: Path, conn: Any
    ) -> None:
        binary_id = store.add_binary(conn, sha256="8" * 64, name="lone.exe", path="/tmp/lone.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=8)

        payload, is_error = _call(
            "bulk_analyses", {"action": "delete", "analysis_ids": [analysis_id]}
        )

        assert is_error is False
        assert payload["applied"] == 0
        assert payload["skipped"] == [{"id": analysis_id, "reason": "only analysis with functions"}]

    def test_bulk_analyses_rejects_an_unknown_action(self, conn: Any) -> None:
        payload, is_error = _call("bulk_analyses", {"action": "explode", "analysis_ids": [1]})
        assert is_error is True
        assert payload["error"] == "invalid bulk request"

    def test_bulk_functions_clears_matches(self, conn: Any, tmp_path: Path) -> None:
        ids = _seed_binary(conn, tmp_path)
        store.record_match(
            conn,
            function_id=ids["first"],
            candidate_function_id=ids["second"],
            similarity=0.5,
            confidence=0.5,
        )
        payload, is_error = _call(
            "bulk_functions", {"action": "clear_matches", "function_ids": [ids["first"]]}
        )
        assert is_error is False
        assert payload["applied"] == 1
        assert store.list_matches(conn, ids["first"]) == []


def test_cli_mcp_help_lists_the_command() -> None:
    result = runner.invoke(cli.app, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "stdio" in result.output
    # The help lays its option table out to the terminal, and on a runner that
    # renders differently from a local one the flag does not survive as text
    # (its column wraps or truncates), so the flag is asserted where it is
    # declared rather than in the layout.
    command = cast(Any, get_command(cli.app))
    assert ["--json"] in [param.opts for param in command.commands["mcp"].params]


def test_cli_mcp_requires_a_workspace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    monkeypatch.delenv("REPORTAL_DB", raising=False)
    result = runner.invoke(cli.app, ["mcp", "--json"])
    assert result.exit_code == 1
    assert "no reportal workspace" in result.output


def test_cli_mcp_runs_the_stdio_loop(
    conn: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_binary(conn, tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(workspace)
    monkeypatch.delenv("REPORTAL_DB", raising=False)
    store.init_db(workspace / "reportal.db")
    request = json.dumps(_request(1, "initialize", _initialize_params()))
    result = runner.invoke(cli.app, ["mcp"], input=request + "\n")
    assert result.exit_code == 0
    response = json.loads(result.stdout.splitlines()[0])
    assert response["result"]["serverInfo"]["name"] == "reportal"


class TestComponentTools:
    def test_list_components_returns_the_registry(self) -> None:
        payload, is_error = _call("list_components")
        assert is_error is False
        entry = next(item for item in payload["components"] if item["name"] == "prepare")
        assert entry["origin"] == "builtin"
        assert entry["reloadable"] is True
        assert entry["requires"] == ["function"]
        assert entry["withdrawable"] is True
        store_entry = next(item for item in payload["components"] if item["name"] == "store")
        assert store_entry["withdrawable"] is False
        assert "nothing" in store_entry["withdraw_reason"]
        assert payload["count"] == len(payload["components"])

    def test_reload_components_reloads_one(self) -> None:
        payload, is_error = _call("reload_components", {"name": "prepare"})
        assert is_error is False
        assert payload["name"] == "prepare"
        assert payload["changed"] is False
        assert payload["module"] == components.BUILTIN_MODULE

    def test_reload_components_reloads_every_reloadable_one(self) -> None:
        payload, is_error = _call("reload_components", {"all": True})
        assert is_error is False
        assert payload["count"] == len(components.components())
        assert payload["skipped"] == []

    def test_reload_components_unknown_name_is_an_error(self) -> None:
        payload, is_error = _call("reload_components", {"name": "no-such-component"})
        assert is_error is True
        assert payload["error"] == "component not found"

    def test_reload_components_needs_a_name_or_all(self) -> None:
        payload, is_error = _call("reload_components", {})
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_reload_components_rejects_a_name_and_all(self) -> None:
        payload, is_error = _call("reload_components", {"name": "prepare", "all": True})
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_reload_components_rejects_an_in_process_registration(self) -> None:
        components.register_component(
            components.Component("probe", frozenset(), frozenset(), lambda ctx: None)
        )
        payload, is_error = _call("reload_components", {"name": "probe"})
        assert is_error is True
        assert payload["error"] == "not-reloadable"

    def test_deactivate_components_withdraws_one(self, portal_db: Path) -> None:
        payload, is_error = _call("deactivate_components", {"name": "prepare"})
        assert is_error is False
        assert payload["name"] == "prepare"
        assert [entry["name"] for entry in payload["deactivated"]] == ["prepare"]
        assert payload["journaled"] is False

    def test_deactivate_components_refuses_a_second_withdrawal(self, portal_db: Path) -> None:
        _call("deactivate_components", {"name": "prepare"})
        payload, is_error = _call("deactivate_components", {"name": "prepare"})
        assert is_error is True
        assert payload["error"] == "not-withdrawable"

    def test_deactivate_components_unknown_name_is_an_error(self, portal_db: Path) -> None:
        payload, is_error = _call("deactivate_components", {"name": "no-such-component"})
        assert is_error is True
        assert payload["error"] == "component not found"

    def test_deactivate_components_refuses_nothing_to_withdraw(self, portal_db: Path) -> None:
        payload, is_error = _call("deactivate_components", {"name": "store"})
        assert is_error is True
        assert payload["error"] == "not-withdrawable"

    def test_deactivate_components_calls_the_withdraw_helper(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        def spy(conn: Any, name: str) -> dict[str, Any]:
            calls.append(name)
            return {
                "name": name,
                "deactivated": [],
                "context_changes": [],
                "active": [],
                "journaled": False,
            }

        monkeypatch.setattr(pipeline, "withdraw_component", spy)
        payload, is_error = _call("deactivate_components", {"name": "prepare"})
        assert is_error is False
        assert payload["name"] == "prepare"
        assert calls == ["prepare"]

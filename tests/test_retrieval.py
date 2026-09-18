"""Tests for knowledge retrieval and its wiring into conversations and the pipeline.

No test touches the network: an unconfigured client is installed process-wide
unless a test injects its own fake.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, FakeLlmClient, json_body, wsgi_request
from pipeline_helpers import ScriptedLlmClient, seed_portal, spy
from typer.testing import CliRunner

from reportal import (
    cli,
    components,
    conversations,
    knowledge,
    llm,
    mcp_server,
    mcp_tools,
    pipeline,
    store,
)
from reportal._paths import DB_ENV

runner = CliRunner()

NOTE = "The dialog uses sub_1000 at 0x1000 for its timer callback.\n"
FONT = "Glyph metrics and kerning pairs for the outline font.\n"
# The text the ranking embeds, with the newline the context renderer collapses.
NOTE_BODY = "The dialog uses sub_1000 at 0x1000 for its timer callback."


@pytest.fixture(autouse=True)
def _no_endpoint() -> Iterator[None]:
    """Install an unconfigured client, so no retrieval reaches the network."""
    llm.set_client(llm.LlmClient(None))
    yield
    llm.set_client(None)


@pytest.fixture(autouse=True)
def _isolate_components() -> Iterator[None]:
    """Reload the component registry around each test, whatever a test registered."""
    components.refresh_components()
    yield
    components.refresh_components()


def _ingest(
    conn: sqlite3.Connection,
    text: str,
    *,
    scope_id: int = 1,
    title: str = "notes",
    source: str = "notes.md",
    scope_kind: str = knowledge.SCOPE_KIND_BINARY,
) -> dict[str, Any]:
    """Ingest *text* as a document of one scope."""
    return knowledge.ingest_document(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        title=title,
        source=source,
        mime="",
        data=text.encode("utf-8"),
    )


def _seed_function(
    conn: sqlite3.Connection,
    *,
    sha: str = "aa" * 32,
    name: str = "sub_1000",
    va: int = 0x1000,
) -> tuple[int, int]:
    """Create a binary and one function; returns (*binary_id*, *function_id*)."""
    binary_id = store.add_binary(conn, sha256=sha, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(conn, analysis_id=analysis_id, va=va, name=name, size=48)
    return binary_id, function_id


class TestRetrieve:
    def test_ranks_the_matching_document(self, conn: sqlite3.Connection) -> None:
        _ingest(conn, NOTE, scope_id=1)
        hits = knowledge.retrieve(conn, query="timer callback", scope_kind="binary", scope_id=1)
        assert hits
        assert hits[0]["title"] == "notes"
        assert hits[0]["method"] == knowledge.METHOD_TFIDF

    def test_blank_query_answers_nothing(self, conn: sqlite3.Connection) -> None:
        _ingest(conn, NOTE, scope_id=1)
        assert knowledge.retrieve(conn, query="   ", scope_kind="binary", scope_id=1) == []

    def test_non_positive_limit_answers_nothing(self, conn: sqlite3.Connection) -> None:
        _ingest(conn, NOTE, scope_id=1)
        hits = knowledge.retrieve(conn, query="timer", scope_kind="binary", scope_id=1, limit=0)
        assert hits == []

    def test_limit_bounds_the_result_list(self, conn: sqlite3.Connection) -> None:
        for index in range(3):
            _ingest(conn, f"widget timer note number {index}\n", scope_id=1)
        hits = knowledge.retrieve(
            conn, query="widget timer", scope_kind="binary", scope_id=1, limit=2
        )
        assert len(hits) == 2

    def test_default_limit_is_the_retrieval_limit(self, conn: sqlite3.Connection) -> None:
        for index in range(knowledge.RETRIEVAL_LIMIT + 2):
            _ingest(conn, f"widget timer note number {index}\n", scope_id=1)
        hits = knowledge.retrieve(conn, query="widget timer", scope_kind="binary", scope_id=1)
        assert len(hits) == knowledge.RETRIEVAL_LIMIT

    def test_scope_filter_keeps_other_scopes_out(self, conn: sqlite3.Connection) -> None:
        first = _ingest(conn, NOTE, scope_id=1, title="one")
        _ingest(conn, NOTE, scope_id=2, title="two")
        hits = knowledge.retrieve(conn, query="timer callback", scope_kind="binary", scope_id=1)
        assert [hit["document_id"] for hit in hits] == [int(first["id"])]

    def test_empty_corpus_answers_nothing(self, conn: sqlite3.Connection) -> None:
        assert knowledge.retrieve(conn, query="timer", scope_kind="binary", scope_id=9) == []

    def test_unknown_term_answers_nothing(self, conn: sqlite3.Connection) -> None:
        _ingest(conn, NOTE, scope_id=1)
        assert knowledge.retrieve(conn, query="zzznotpresent") == []


class TestAsContext:
    def test_formats_one_citable_line_per_hit(self) -> None:
        hits = [{"title": "T", "source": "s.md", "text": "hello   world"}]
        assert knowledge.as_context(hits) == "[1] T (s.md): hello world"

    def test_numbers_each_line_in_rank_order(self) -> None:
        hits = [
            {"title": "one", "source": "a.md", "text": "alpha"},
            {"title": "two", "source": "b.md", "text": "beta"},
        ]
        block = knowledge.as_context(hits)
        assert block.splitlines() == ["[1] one (a.md): alpha", "[2] two (b.md): beta"]

    def test_empty_hits_render_nothing(self) -> None:
        assert knowledge.as_context([]) == ""

    def test_whitespace_is_collapsed_to_one_line(self) -> None:
        hits = [{"title": "t", "source": "s", "text": "line one\n\n  line\ttwo"}]
        assert knowledge.as_context(hits) == "[1] t (s): line one line two"

    def test_snippet_is_truncated_to_the_named_constant(self) -> None:
        hits = [{"title": "t", "source": "s.md", "text": "a" * 900}]
        line = knowledge.as_context(hits, max_chars=10_000)
        snippet = line.split(": ", 1)[1]
        assert len(snippet) == knowledge.RETRIEVAL_SNIPPET_CHARS
        assert snippet.endswith("…")

    def test_a_snippet_at_the_limit_is_not_truncated(self) -> None:
        text = "a" * knowledge.RETRIEVAL_SNIPPET_CHARS
        block = knowledge.as_context([{"title": "t", "source": "s", "text": text}])
        assert block.endswith(text)

    def test_a_hit_over_the_budget_is_dropped(self) -> None:
        first = {"title": "one", "source": "a.md", "text": "alpha"}
        block = knowledge.as_context([first], max_chars=100)
        assert block == "[1] one (a.md): alpha"
        assert knowledge.as_context([first], max_chars=len(block) - 1) == ""

    def test_a_big_middle_hit_is_skipped_and_the_next_one_kept(self) -> None:
        small = {"title": "s", "source": "a.md", "text": "x"}
        big = {"title": "b" * 100, "source": "b.md", "text": "y" * 400}
        line = knowledge.as_context([small])
        block = knowledge.as_context([small, big, small], max_chars=2 * len(line) + 1)
        assert block == "[1] s (a.md): x\n[2] s (a.md): x"

    def test_zero_budget_renders_nothing(self) -> None:
        hits = [{"title": "t", "source": "s", "text": "text"}]
        assert knowledge.as_context(hits, max_chars=0) == ""


class TestConversationContext:
    def test_message_matching_a_document_appends_the_section(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        context = conversations.build_context(
            conn,
            scope_kind="function",
            scope_id=function_id,
            message="what is the timer callback",
        )
        assert conversations.DOCUMENT_SECTION_HEADER in context
        assert NOTE_BODY in context

    def test_no_matching_document_omits_the_section(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        context = conversations.build_context(
            conn,
            scope_kind="function",
            scope_id=function_id,
            message="zzznotinthecorpus",
        )
        assert conversations.DOCUMENT_SECTION_HEADER not in context

    def test_no_documents_omits_the_section(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seed_function(conn)
        context = conversations.build_context(
            conn, scope_kind="function", scope_id=function_id, message="timer"
        )
        assert conversations.DOCUMENT_SECTION_HEADER not in context

    def test_blank_message_omits_the_section(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        context = conversations.build_context(
            conn, scope_kind="function", scope_id=function_id, message=""
        )
        assert conversations.DOCUMENT_SECTION_HEADER not in context

    def test_function_scope_reads_its_own_binarys_documents(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn, sha="aa" * 32)
        other = store.add_binary(conn, sha256="bb" * 32, name="other.exe", path="/x/other.exe")
        _ingest(conn, NOTE, scope_id=other, title="foreign")
        context = conversations.build_context(
            conn, scope_kind="function", scope_id=function_id, message="timer callback"
        )
        assert conversations.DOCUMENT_SECTION_HEADER not in context
        _ingest(conn, NOTE, scope_id=binary_id, title="own")
        context = conversations.build_context(
            conn, scope_kind="function", scope_id=function_id, message="timer callback"
        )
        assert "own" in context

    def test_binary_scope_reads_its_documents(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        context = conversations.build_context(
            conn, scope_kind="binary", scope_id=binary_id, message="timer callback"
        )
        assert conversations.DOCUMENT_SECTION_HEADER in context

    def test_overall_budget_is_respected(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn)
        store.set_disasm(conn, function_id, "nop\n" * (conversations.MAX_CONTEXT_CHARS * 2))
        _ingest(conn, NOTE, scope_id=binary_id)
        context = conversations.build_context(
            conn, scope_kind="function", scope_id=function_id, message="timer callback"
        )
        assert len(context) == conversations.MAX_CONTEXT_CHARS
        assert context.endswith(conversations.TRUNCATION_MARKER)
        assert conversations.DOCUMENT_SECTION_HEADER not in context

    def test_unknown_scope_is_empty(self, conn: sqlite3.Connection) -> None:
        assert (
            conversations.build_context(conn, scope_kind="galaxy", scope_id=1, message="timer")
            == ""
        )

    def test_scope_knowledge_returns_the_hits(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        hits = conversations.scope_knowledge(
            conn, scope_kind="function", scope_id=function_id, message="timer callback"
        )
        assert hits and hits[0]["title"] == "notes"


class TestSendMessage:
    def test_sends_the_retrieved_snippet_and_returns_the_sources(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        conversation_id = store.create_conversation(
            conn, scope_kind="function", scope_id=function_id, title="chat"
        )
        result = conversations.send_message(
            conn, conversation_id=conversation_id, content="what is the timer callback"
        )
        sent = fake_llm.calls[0]
        assert conversations.SYSTEM_PROMPT in sent[0]["content"]
        stored_context = json.loads(sent[1]["content"])["stored_context"]
        assert conversations.DOCUMENT_SECTION_HEADER in stored_context
        assert NOTE_BODY in stored_context
        assert result["sources"]
        assert result["sources"][0]["title"] == "notes"

    def test_no_match_sends_no_sources(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        conversation_id = store.create_conversation(
            conn, scope_kind="function", scope_id=function_id, title="chat"
        )
        result = conversations.send_message(
            conn, conversation_id=conversation_id, content="zzznotinthecorpus"
        )
        assert result["sources"] == []
        assert conversations.DOCUMENT_SECTION_HEADER not in fake_llm.calls[0][0]["content"]


class TestPipelineComponent:
    def _run(
        self,
        conn: sqlite3.Connection,
        ids: dict[str, int],
        *,
        llm_client: llm.LlmClient | None = None,
    ) -> dict[str, Any]:
        return pipeline.run_pipeline(
            conn,
            function_id=ids["function"],
            engine=FakeEngine(),
            llm_client=llm_client,
        )

    def test_provides_the_knowledge_hits(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        _ingest(conn, NOTE, scope_id=ids["binary"])
        captured: dict[str, Any] = {}
        components.register_component(spy("knowledge-spy", {"knowledge"}, captured))
        self._run(conn, ids, llm_client=ScriptedLlmClient())
        hits = captured["knowledge"]
        assert isinstance(hits, list)
        assert hits and hits[0]["title"] == "notes"

    def test_runs_without_an_llm(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = pipeline.run_pipeline(conn, function_id=ids["function"], engine=FakeEngine())
        steps = {str(step["name"]): step for step in run["steps"]}
        assert steps["retrieve-knowledge"]["status"] == pipeline.STEP_DONE
        assert steps["retrieve-knowledge"]["provides"] == ["knowledge"]

    def test_is_ordered_between_resolve_names_and_the_llm_stages(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        run = self._run(conn, ids, llm_client=ScriptedLlmClient())
        names = [str(step["name"]) for step in run["steps"]]
        position = names.index("retrieve-knowledge")
        assert names.index("resolve-names") < position
        assert position < names.index("name-variables")
        assert position < names.index("summarize")

    def test_empty_list_without_documents(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        captured: dict[str, Any] = {}
        components.register_component(spy("knowledge-spy", {"knowledge"}, captured))
        self._run(conn, ids, llm_client=ScriptedLlmClient())
        assert captured["knowledge"] == []

    def test_summarize_prompt_carries_the_retrieved_text(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        _ingest(conn, NOTE, scope_id=ids["binary"])
        client = ScriptedLlmClient()
        self._run(conn, ids, llm_client=client)
        summary_prompts = [
            messages[-1]["content"]
            for messages in client.calls
            if "Summarize" in messages[-1]["content"]
        ]
        assert summary_prompts
        assert all(NOTE_BODY in prompt for prompt in summary_prompts)

    def test_name_variables_prompts_carry_the_retrieved_text(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        _ingest(conn, NOTE, scope_id=ids["binary"])
        client = ScriptedLlmClient()
        self._run(conn, ids, llm_client=client)
        variables_prompts = [
            messages[-1]["content"]
            for messages in client.calls
            if "Summarize" not in messages[-1]["content"]
        ]
        assert variables_prompts
        assert all(NOTE_BODY in prompt for prompt in variables_prompts)

    def test_prompts_omit_the_block_without_documents(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        client = ScriptedLlmClient()
        self._run(conn, ids, llm_client=client)
        assert client.calls
        assert all(
            "Retrieved documents" not in messages[-1]["content"] for messages in client.calls
        )

    def test_query_names_the_function_and_its_summary(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_portal(tmp_path, monkeypatch)
        store.set_ai_artifact(
            conn, ids["function"], llm.AI_KIND_SUMMARY, {"summary": "draws the dialog"}, "m"
        )
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert pipeline._knowledge_query(conn, function) == "sub_1000 0x1000 draws the dialog"


class TestKnowledgeApi:
    def test_function_route_ranks_its_binarys_documents(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        status, headers, raw = wsgi_request(
            "GET", f"/api/functions/{function_id}/knowledge?q=timer"
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["query"] == "timer"
        assert payload["count"] >= 1
        assert payload["results"][0]["title"] == "notes"

    def test_function_route_defaults_the_query_to_the_name(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        status, headers, raw = wsgi_request("GET", f"/api/functions/{function_id}/knowledge")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["query"] == "sub_1000"
        assert payload["count"] >= 1

    def test_binary_route_ranks_its_documents(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id, _ = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        status, headers, raw = wsgi_request("GET", f"/api/binaries/{binary_id}/knowledge?q=timer")
        assert status.startswith("200")
        assert json_body(raw, headers)["count"] >= 1

    def test_binary_route_blank_query_is_empty(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id, _ = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        status, headers, raw = wsgi_request("GET", f"/api/binaries/{binary_id}/knowledge?q=")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["count"] == 0
        assert payload["results"] == []

    def test_unknown_function_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/functions/999/knowledge?q=x")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "function not found"

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/binaries/999/knowledge?q=x")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"


class TestContextCli:
    def _portal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_document: bool = True
    ) -> dict[str, int]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id, function_id = _seed_function(conn)
            if with_document:
                _ingest(conn, NOTE, scope_id=binary_id)
        return {"binary": binary_id, "function": function_id}

    def test_json_prints_the_retrieved_hits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["context", str(ids["function"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["function_id"] == ids["function"]
        assert payload["query"] == "sub_1000"
        assert payload["count"] >= 1
        assert payload["results"][0]["title"] == "notes"

    def test_query_option_overrides_the_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["context", str(ids["function"]), "--query", "timer", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["query"] == "timer"
        assert payload["count"] >= 1

    def test_human_output_prints_the_snippet(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["context", str(ids["function"])])
        assert result.exit_code == 0, result.output
        assert "notes" in result.output
        assert "timer callback" in result.output

    def test_no_match_prints_a_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._portal(tmp_path, monkeypatch, with_document=False)
        result = runner.invoke(cli.app, ["context", str(ids["function"])])
        assert result.exit_code == 0, result.output
        assert "No matches." in result.output

    def test_unknown_function_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["context", "404"])
        assert result.exit_code == 1
        assert "no function with id 404" in result.output


class TestMcpTool:
    def _call(self, name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
        return mcp_server.call_tool(name, arguments)

    def test_tool_is_registered_read_only(self) -> None:
        tool = next(
            (entry for entry in mcp_tools.tools() if entry.name == "retrieve_knowledge"),
            None,
        )
        assert tool is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False

    def test_scopes_to_a_functions_binary(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        payload, is_error = self._call(
            "retrieve_knowledge", {"query": "timer callback", "function_id": function_id}
        )
        assert is_error is False
        assert payload["count"] >= 1
        assert payload["results"][0]["title"] == "notes"

    def test_scopes_to_a_binary(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_function(conn)
        _ingest(conn, NOTE, scope_id=binary_id)
        payload, is_error = self._call(
            "retrieve_knowledge", {"query": "timer callback", "binary_id": binary_id}
        )
        assert is_error is False
        assert payload["count"] >= 1

    def test_limit_is_bounded(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_function(conn)
        for index in range(3):
            _ingest(conn, f"widget timer note number {index}\n", scope_id=binary_id)
        payload, is_error = self._call(
            "retrieve_knowledge", {"query": "widget timer", "binary_id": binary_id, "limit": 1}
        )
        assert is_error is False
        assert len(payload["results"]) == 1

    def test_non_positive_limit_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, is_error = self._call("retrieve_knowledge", {"query": "x", "limit": 0})
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_unknown_function_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, is_error = self._call("retrieve_knowledge", {"query": "x", "function_id": 999})
        assert is_error is True
        assert payload["error"] == "function not found"

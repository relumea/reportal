"""Tests for the agentic conversation runs.

The tool loop is driven with a scripted client (the model's turns are canned,
the tools are the real registry), so the run, the confirmation gate, the cancel
and the SSE state stream are all exercised without a network call.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import agent, cli, journal, llm, mcp_server, store
from reportal._paths import DB_ENV

runner = CliRunner()


class ScriptedAgentClient(llm.LlmClient):
    """A typed stub whose turns are scripted: no network, a call log."""

    def __init__(self, turns: list[dict[str, Any]]) -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model="fake-model"))
        self.turns = list(turns)
        self.calls: list[list[dict[str, Any]]] = []
        self.tools_seen: list[Any] = []

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        max_tokens: int = llm.MAX_AGENT_TOKENS,
    ) -> dict[str, Any]:
        del max_tokens
        self.calls.append(messages)
        self.tools_seen.append(tools)
        turn = self.turns.pop(0) if self.turns else {"content": "done"}
        return {
            "content": turn.get("content", ""),
            "tool_calls": turn.get("tool_calls", []),
            "finish_reason": turn.get("finish_reason", "stop"),
        }


class FailingAgentClient(llm.LlmClient):
    """A typed stub whose request always fails."""

    def __init__(self, message: str = "model exploded") -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model="fake-model"))
        self.message = message

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        max_tokens: int = llm.MAX_AGENT_TOKENS,
    ) -> dict[str, Any]:
        del messages, tools, temperature, max_tokens
        raise llm.LlmError(self.message)


def _call(name: str, arguments: str = "{}", call_id: str = "call-1") -> dict[str, Any]:
    return {"id": call_id, "name": name, "arguments": arguments}


def _tag_call(ids: dict[str, Any], call_id: str = "call-1") -> dict[str, Any]:
    """A destructive tool call: tags the seeded binary."""
    arguments = json.dumps({"binary_id": ids["binary"], "name": "agent"})
    return _call("tag_binary", arguments, call_id)


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A portal DB with one binary, one analysis, one function and one chat."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_0")
        conversation_id = store.create_conversation(
            conn, scope_kind="function", scope_id=function_id, title="chat"
        )
    return {
        "binary": binary_id,
        "analysis": analysis_id,
        "function": function_id,
        "conversation": conversation_id,
        "db": db,
    }


def _journaled(conn: sqlite3.Connection, body: Any) -> Any:
    """Run *body* inside one journaled action, as the routes do."""
    with journal.journaled(conn, journal.new_action()) as log:
        return body(conn, log)


class TestToolDefinitions:
    def test_every_registered_tool_is_offered_with_its_own_schema(self) -> None:
        definitions = agent.tool_definitions()
        names = {entry["function"]["name"] for entry in definitions}
        assert "get_function" in names
        assert len(definitions) == len(_registry_tools())
        entry = next(row for row in definitions if row["function"]["name"] == "get_function")
        assert entry["type"] == "function"
        assert entry["function"]["parameters"]["type"] == "object"

    def test_the_destructive_split_follows_the_registry(self) -> None:
        destructive = agent.destructive_tools()
        assert "add_comment" in destructive
        assert "get_function" not in destructive
        assert agent.is_destructive("definitely-not-a-tool") is True


def _registry_tools() -> list[Any]:
    """The live MCP registry, read through the module the server uses."""
    from reportal import mcp_tools

    return list(mcp_tools.tools())


class TestRuns:
    def test_a_read_only_tool_runs_and_the_answer_is_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {
                    "tool_calls": [
                        _call("get_function", json.dumps({"function_id": ids["function"]}))
                    ]
                },
                {"content": "the function is sub_0"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="what is this?",
                    client=client,
                ),
            )
            messages = store.list_messages(conn, ids["conversation"])
        assert payload["status"] == agent.STATUS_COMPLETED
        assert payload["content"] == "the function is sub_0"
        assert payload["tool_calls"] == 1
        assert [entry["kind"] for entry in payload["events"]] == [
            agent.EVENT_STARTED,
            agent.EVENT_TOOL_CALL,
            agent.EVENT_MESSAGE,
        ]
        assert [row["role"] for row in messages] == ["user", "assistant"]
        assert client.tools_seen[0]

    def test_a_destructive_tool_pauses_for_confirmation_and_runs_on_approval(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {
                    "tool_calls": [
                        _call(
                            "add_comment",
                            json.dumps(
                                {
                                    "scope_kind": "function",
                                    "scope_id": ids["function"],
                                    "body": "from the agent",
                                }
                            ),
                        )
                    ]
                },
                {"content": "commented"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            paused = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="comment on it",
                    client=client,
                ),
            )
            assert paused["status"] == agent.STATUS_WAITING
            assert paused["pending"]["name"] == "add_comment"
            assert paused["content"] == ""
            comments_before = store.list_comments(
                conn, scope_kind="function", scope_id=ids["function"]
            )
            assert comments_before == []

            finished = _journaled(
                conn,
                lambda conn, log: agent.confirm(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    approve=True,
                    client=client,
                ),
            )
            comments = store.list_comments(conn, scope_kind="function", scope_id=ids["function"])
        assert finished["status"] == agent.STATUS_COMPLETED
        assert finished["content"] == "commented"
        assert [row["body"] for row in comments] == ["from the agent"]
        assert finished["pending"] is None

    def test_a_rejected_call_is_fed_back_and_the_run_continues(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {"tool_calls": [_tag_call(ids)]},
                {"content": "I will not delete it"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="delete it",
                    client=client,
                ),
            )
            finished = _journaled(
                conn,
                lambda conn, log: agent.confirm(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    approve=False,
                    client=client,
                ),
            )
            assert store.get_binary(conn, ids["binary"]) is not None
        assert finished["status"] == agent.STATUS_COMPLETED
        assert [entry["kind"] for entry in finished["events"]] == [
            agent.EVENT_STARTED,
            agent.EVENT_CONFIRMATION_REQUIRED,
            agent.EVENT_TOOL_REJECTED,
            agent.EVENT_MESSAGE,
        ]

    def test_the_tool_call_limit_fails_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        calls = [
            {"tool_calls": [_call("list_binaries", "{}", f"call-{index}")]}
            for index in range(agent.MAX_TOOL_CALLS + 2)
        ]
        client = ScriptedAgentClient(calls)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
        assert payload["status"] == agent.STATUS_FAILED
        assert payload["tool_calls"] == agent.MAX_TOOL_CALLS
        assert "limit" in payload["error"]
        assert payload["events"][-1]["kind"] == agent.EVENT_LIMIT

    def test_unparsable_arguments_are_fed_back_to_the_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {"tool_calls": [_call("get_function", "{not json")]},
                {"content": "fixed"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
        assert payload["status"] == agent.STATUS_COMPLETED
        assert payload["content"] == "fixed"
        tool_event = payload["events"][1]
        assert "not valid JSON" in tool_event["error"]

    def test_a_failed_model_call_fails_the_run_and_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            with pytest.raises(llm.LlmError):
                _journaled(
                    conn,
                    lambda conn, log: agent.start(
                        conn,
                        log,
                        conversation_id=ids["conversation"],
                        content="go",
                        client=FailingAgentClient(),
                    ),
                )
            runs = agent.list_runs(conn, ids["conversation"])
        assert runs[0]["status"] == agent.STATUS_FAILED
        assert "model exploded" in runs[0]["error"]

    def test_an_unknown_conversation_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(KeyError),
        ):
            _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn, log, conversation_id=999, content="go", client=ScriptedAgentClient([])
                ),
            )

    def test_the_run_row_and_the_messages_revert_together(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient([{"content": "hello"}])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="hi",
                    client=client,
                )
            assert agent.list_runs(conn, ids["conversation"])
            assert journal.revert_action(conn, action)["reverted"] > 0
            assert agent.list_runs(conn, ids["conversation"]) == []
            assert store.list_messages(conn, ids["conversation"]) == []

    def test_cancel_stops_a_live_run_and_refuses_a_finished_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient([{"tool_calls": [_tag_call(ids)]}])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
            cancelled = agent.cancel(conn, conversation_id=ids["conversation"])
            assert cancelled["status"] == agent.STATUS_CANCELLED
            with pytest.raises(agent.NotCancellableError):
                agent.cancel(conn, conversation_id=ids["conversation"])

    def test_a_run_resumes_where_it_paused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {"tool_calls": [_tag_call(ids)]},
                {"content": "resumed"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            paused = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
            stored = agent._stored_messages(conn, int(paused["run_id"]))
            assert [row["role"] for row in stored] == ["system", "user", "assistant"]
            assert stored[2]["tool_calls"][0]["function"]["name"] == "tag_binary"

            resumed = _journaled(
                conn,
                lambda conn, log: agent.confirm(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    approve=True,
                    client=client,
                ),
            )
            tags = [row["name"] for row in store.get_binary_tags(conn, ids["binary"])]
        assert resumed["run_id"] == paused["run_id"]
        assert resumed["status"] == agent.STATUS_COMPLETED
        assert resumed["content"] == "resumed"
        assert tags == ["agent"]
        assert [entry["kind"] for entry in resumed["events"]][-2:] == [
            agent.EVENT_TOOL_CALL,
            agent.EVENT_MESSAGE,
        ]

    def test_get_run_and_resolve_run_report_unknown_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            with pytest.raises(agent.UnknownRunError):
                agent.get_run(conn, 999)
            with pytest.raises(agent.UnknownRunError):
                agent.resolve_run(conn, ids["conversation"], None)
            assert agent.latest_run(conn, ids["conversation"]) is None


class TestBounds:
    def test_the_destructive_split_reads_the_registry(self) -> None:
        assert agent.is_destructive("get_function") is False
        assert agent.is_destructive("add_comment") is True
        assert agent.is_destructive("not-a-registered-tool") is True

    def test_a_tool_result_is_bounded_and_labelled(self) -> None:
        long = agent._tool_result_text({"value": "x" * (agent.MAX_TOOL_RESULT_CHARS * 2)}, False)
        assert len(long) == agent.MAX_TOOL_RESULT_CHARS
        assert long.endswith(agent.TOOL_RESULT_MARKER)
        failed = agent._tool_result_text({"error": "no"}, True)
        assert json.loads(failed)["tool_error"] == {"error": "no"}

    def test_arguments_are_bounded_and_must_be_an_object(self) -> None:
        assert agent._parse_arguments("") == ({}, "")
        assert agent._parse_arguments('{"a": 1}') == ({"a": 1}, "")
        over, error = agent._parse_arguments("x" * (agent.MAX_ARGUMENT_CHARS + 1))
        assert over is None
        assert "exceed" in error
        assert agent._parse_arguments("[1]")[0] is None
        assert "must be a JSON object" in agent._parse_arguments("[1]")[1]

    def test_a_refused_tool_call_becomes_a_failed_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient(
            [
                {"tool_calls": [_call("get_function", "{}")]},
                {"content": "gave up"},
            ]
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
        assert payload["status"] == agent.STATUS_COMPLETED
        tool_event = payload["events"][1]
        assert tool_event["failed"] is True
        assert "tool call refused" in tool_event["result"]

    def test_a_model_turn_without_text_or_a_call_fails_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient([{"content": "   "}])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
        assert payload["status"] == agent.STATUS_FAILED
        assert "no text" in payload["error"]

    def test_a_run_cancelled_between_steps_stops_there(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)

        class CancellingClient(ScriptedAgentClient):
            """Cancels the run from inside the model call, as another request would."""

            def __init__(self, turns: list[dict[str, Any]], db: Path) -> None:
                super().__init__(turns)
                self.db = db

            def chat(
                self,
                messages: list[dict[str, Any]],
                *,
                tools: list[dict[str, Any]] | None = None,
                temperature: float = llm.DEFAULT_TEMPERATURE,
                max_tokens: int = llm.MAX_AGENT_TOKENS,
            ) -> dict[str, Any]:
                with contextlib.closing(store.connect(self.db)) as conn:
                    agent.cancel(conn, conversation_id=ids["conversation"])
                return super().chat(
                    messages,
                    tools=tools,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

        client = CancellingClient([{"tool_calls": [_call("list_binaries")]}], ids["db"])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
        # The step in flight (the model call and the tool it asked for) finished;
        # the loop stopped at the next boundary and the cancel holds.
        assert payload["status"] == agent.STATUS_CANCELLED
        assert payload["tool_calls"] == 1
        assert payload["content"] == ""

    def test_stored_messages_of_an_unknown_run_are_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            assert agent._stored_messages(conn, 999) == []

    def test_resolve_run_refuses_a_run_of_another_conversation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            other = store.create_conversation(
                conn, scope_kind="binary", scope_id=ids["binary"], title="other"
            )
            client = ScriptedAgentClient([{"content": "hello"}])
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="hi",
                    client=client,
                ),
            )
            with pytest.raises(agent.UnknownRunError):
                agent.resolve_run(conn, other, int(payload["run_id"]))

    def test_a_live_stream_times_out_at_its_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient([{"tool_calls": [_tag_call(ids)]}])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            paused = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="go",
                    client=client,
                ),
            )
            frames = list(agent.events(conn, int(paused["run_id"]), interval=0.0, max_seconds=0.0))
        assert frames[-1] == "event: timeout\ndata: {}\n\n"
        assert len(frames) == 2


class TestEventStream:
    def test_the_stream_ends_on_a_terminal_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        client = ScriptedAgentClient([{"content": "hello"}])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = _journaled(
                conn,
                lambda conn, log: agent.start(
                    conn,
                    log,
                    conversation_id=ids["conversation"],
                    content="hi",
                    client=client,
                ),
            )
            frames = list(agent.events(conn, int(payload["run_id"]), interval=0.0))
        assert frames[0].startswith("event: run")
        assert '"completed"' in frames[0]
        assert len(frames) == 1

    def test_an_unknown_run_streams_one_error_frame(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            frames = list(agent.events(conn, 999, interval=0.0))
        assert frames == [
            f"event: error\ndata: {json.dumps({'error': agent.ERROR_RUN_NOT_FOUND})}\n\n"
        ]


class TestRoutes:
    def _start(self, ids: dict[str, Any]) -> Any:
        return wsgi_request(
            "POST",
            f"/api/conversations/{ids['conversation']}/runs",
            body=json.dumps({"content": "hi"}),
        )

    def test_a_run_route_reports_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(ScriptedAgentClient([{"content": "hello"}]))
        status, headers, body = self._start(ids)
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["status"] == agent.STATUS_COMPLETED
        assert payload["journal_action"]

        listed, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/runs"
        )
        assert json_body(body, headers)["count"] == 1

        one, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/runs/{payload['run_id']}"
        )
        assert one.startswith("200")
        assert json_body(body, headers)["run_id"] == payload["run_id"]

    def test_the_route_answers_503_without_an_endpoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(None)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{ids['conversation']}/runs",
            body=json.dumps({"content": "hi"}),
        )
        assert status.startswith("503"), body
        assert json_body(body, headers)["error"] == "llm-unavailable"

    def test_the_route_validates_its_body_and_its_conversation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(ScriptedAgentClient([{"content": "hello"}]))
        bad, _, _ = wsgi_request(
            "POST", f"/api/conversations/{ids['conversation']}/runs", body=json.dumps({})
        )
        assert bad.startswith("400")
        missing, headers, body = wsgi_request(
            "POST", "/api/conversations/999/runs", body=json.dumps({"content": "hi"})
        )
        assert missing.startswith("404")
        assert json_body(body, headers)["error"] == "conversation not found"
        for url in (
            "/api/conversations/999/runs",
            "/api/conversations/999/events",
        ):
            gone, _, _ = wsgi_request("GET", url)
            assert gone.startswith("404"), url

    def test_the_confirm_cancel_and_events_routes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(
            ScriptedAgentClient(
                [
                    {"tool_calls": [_tag_call(ids)]},
                    {"content": "rejected"},
                ]
            )
        )
        status, headers, body = self._start(ids)
        payload = json_body(body, headers)
        assert payload["status"] == agent.STATUS_WAITING

        bad, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{ids['conversation']}/confirm",
            body=json.dumps({"approve": "yes"}),
        )
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid approval"

        confirmed, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{ids['conversation']}/confirm",
            body=json.dumps({"approve": False}),
        )
        assert confirmed.startswith("200"), body
        assert json_body(body, headers)["status"] == agent.STATUS_COMPLETED

        again, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{ids['conversation']}/confirm",
            body=json.dumps({"approve": True}),
        )
        assert again.startswith("409")
        assert json_body(body, headers)["error"] == agent.ERROR_NOT_WAITING

        cancelled, headers, body = wsgi_request(
            "POST", f"/api/conversations/{ids['conversation']}/cancel", body=json.dumps({})
        )
        assert cancelled.startswith("409"), body
        assert json_body(body, headers)["error"] == agent.ERROR_NOT_CANCELLABLE

        events, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/events"
        )
        assert events.startswith("200"), body
        assert headers.get("Content-Type", "").startswith("text/event-stream")
        assert "event: run" in body.decode()

        bad_id, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/events?run_id=x"
        )
        assert bad_id.startswith("400")

    def test_the_run_routes_report_an_unknown_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(ScriptedAgentClient([{"content": "hello"}]))
        self._start(ids)
        missing, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/runs/999"
        )
        assert missing.startswith("404")
        assert json_body(body, headers)["error"] == agent.ERROR_RUN_NOT_FOUND
        none_yet, headers, body = wsgi_request(
            "GET", f"/api/conversations/{ids['conversation']}/events?run_id=999"
        )
        assert none_yet.startswith("404")


class TestCli:
    def test_the_run_commands(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(ScriptedAgentClient([{"content": "hello"}]))
        conversation = str(ids["conversation"])
        started = runner.invoke(cli.app, ["conversation-run", conversation, "hi", "--json"])
        assert started.exit_code == 0, started.output
        payload = json.loads(started.output)
        assert payload["status"] == agent.STATUS_COMPLETED
        assert payload["journal_action"]

        human = runner.invoke(cli.app, ["conversation-run", conversation, "again"])
        assert human.exit_code == 0, human.output
        assert "assistant" in human.output

        listed = runner.invoke(cli.app, ["conversation-runs", conversation, "--json"])
        assert json.loads(listed.output)["count"] == 2

        status = runner.invoke(cli.app, ["conversation-run-status", conversation, "--json"])
        assert json.loads(status.output)["status"] == agent.STATUS_COMPLETED

        table = runner.invoke(cli.app, ["conversation-runs", conversation])
        assert table.exit_code == 0, table.output
        assert "agent runs" in table.output

        plain = runner.invoke(cli.app, ["conversation-run-status", conversation])
        assert plain.exit_code == 0, plain.output
        assert "assistant" in plain.output

    def test_the_confirmation_commands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        conversation = str(ids["conversation"])
        llm.set_client(
            ScriptedAgentClient(
                [
                    {"tool_calls": [_tag_call(ids)]},
                    {"content": "stopped"},
                ]
            )
        )
        paused = runner.invoke(cli.app, ["conversation-run", conversation, "go"])
        assert paused.exit_code == 0, paused.output
        assert "confirmation required" in paused.output

        confirmed = runner.invoke(cli.app, ["conversation-confirm", conversation, "--reject"])
        assert confirmed.exit_code == 0, confirmed.output
        assert "rejected" in confirmed.output

        cancelled = runner.invoke(cli.app, ["conversation-cancel", conversation])
        assert cancelled.exit_code == 1
        assert agent.ERROR_NOT_CANCELLABLE in cancelled.output

        events = runner.invoke(cli.app, ["conversation-events", conversation])
        assert events.exit_code == 0, events.output
        assert "event: run" in events.output

    def test_the_commands_fail_without_an_endpoint_or_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        conversation = str(ids["conversation"])
        llm.set_client(None)
        offline = runner.invoke(cli.app, ["conversation-run", conversation, "hi"])
        assert offline.exit_code == 1
        assert "llm-unavailable" in offline.output

        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["conversation-run", "1", "hi"],
            ["conversation-runs", "1"],
            ["conversation-run-status", "1"],
            ["conversation-confirm", "1"],
            ["conversation-cancel", "1"],
            ["conversation-events", "1"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestMcp:
    def test_the_run_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(
            ScriptedAgentClient(
                [
                    {
                        "tool_calls": [
                            _call("get_function", json.dumps({"function_id": ids["function"]}))
                        ]
                    },
                    {"content": "answered"},
                ]
            )
        )
        payload, failed = mcp_server.call_tool(
            "run_conversation_agent",
            {"conversation_id": ids["conversation"], "content": "hi"},
        )
        assert not failed, payload
        assert payload["status"] == agent.STATUS_COMPLETED
        assert payload["journal_action"]

        runs, failed = mcp_server.call_tool(
            "list_conversation_runs", {"conversation_id": ids["conversation"]}
        )
        assert not failed, runs
        assert runs["count"] == 1

        one, failed = mcp_server.call_tool(
            "get_conversation_run", {"conversation_id": ids["conversation"]}
        )
        assert not failed, one
        assert one["content"] == "answered"
        assert one["tool_calls"] == 1

        unknown, failed = mcp_server.call_tool(
            "get_conversation_run", {"conversation_id": ids["conversation"], "run_id": 999}
        )
        assert failed
        assert unknown["error"] == agent.ERROR_RUN_NOT_FOUND

        missing, failed = mcp_server.call_tool("list_conversation_runs", {"conversation_id": 999})
        assert failed
        assert missing["error"] == "conversation not found"

    def test_the_confirmation_and_cancel_tools(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(
            ScriptedAgentClient(
                [
                    {"tool_calls": [_tag_call(ids)]},
                    {"content": "stopped"},
                ]
            )
        )
        paused, failed = mcp_server.call_tool(
            "run_conversation_agent",
            {"conversation_id": ids["conversation"], "content": "go"},
        )
        assert not failed, paused
        assert paused["status"] == agent.STATUS_WAITING

        rejected, failed = mcp_server.call_tool(
            "confirm_conversation_run",
            {"conversation_id": ids["conversation"], "approve": False},
        )
        assert not failed, rejected
        assert rejected["status"] == agent.STATUS_COMPLETED

        not_waiting, failed = mcp_server.call_tool(
            "confirm_conversation_run", {"conversation_id": ids["conversation"]}
        )
        assert failed
        assert not_waiting["error"] == agent.ERROR_NOT_WAITING

        refused, failed = mcp_server.call_tool(
            "cancel_conversation_run", {"conversation_id": ids["conversation"]}
        )
        assert failed
        assert refused["error"] == agent.ERROR_NOT_CANCELLABLE

        llm.set_client(None)
        unconfigured, failed = mcp_server.call_tool(
            "run_conversation_agent",
            {"conversation_id": ids["conversation"], "content": "go"},
        )
        assert failed
        assert unconfigured["error"] == "llm-unavailable"

    def test_cancelling_a_paused_run_over_mcp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        llm.set_client(ScriptedAgentClient([{"tool_calls": [_tag_call(ids)]}]))
        paused, failed = mcp_server.call_tool(
            "run_conversation_agent",
            {"conversation_id": ids["conversation"], "content": "go"},
        )
        assert not failed, paused
        cancelled, failed = mcp_server.call_tool(
            "cancel_conversation_run", {"conversation_id": ids["conversation"]}
        )
        assert not failed, cancelled
        assert cancelled["status"] == agent.STATUS_CANCELLED

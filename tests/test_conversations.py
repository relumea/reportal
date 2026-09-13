"""Tests for conversations: stored context, prompt assembly and the LLM call.

No test touches the network: the LLM client is the conftest fake, injected
either directly into `send_message` or process-wide through `llm.set_client`.
"""

from __future__ import annotations

import sqlite3

import pytest
from conftest import ANALYSIS, FailingLlmClient, FakeLlmClient

from reportal import conversations, llm, store

FUNCTION_CODE = "int f(void) { return 1; }"
FUNCTION_DISASM = "bits 32\n\nsub_1000:\n  mov eax, 1\n  ret\n"


def _seed_function(conn: sqlite3.Connection) -> int:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=48, status="STUB"
    )


def _seed_binary(conn: sqlite3.Connection) -> int:
    return store.add_binary(conn, sha256="bb" * 32, name="demo.exe", path="/x/demo.exe")


def _new_conversation(
    conn: sqlite3.Connection, *, scope_kind: str = "function", scope_id: int = 1
) -> int:
    return store.create_conversation(conn, scope_kind=scope_kind, scope_id=scope_id, title="chat")


class TestBuildContext:
    def test_function_scope_with_stored_data(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_disasm(conn, function_id, FUNCTION_DISASM)
        store.set_decompilation(conn, function_id, FUNCTION_CODE, "kuna")
        context = conversations.build_context(conn, scope_kind="function", scope_id=function_id)
        assert "0x1000" in context
        assert "sub_1000" in context
        assert "48 bytes" in context
        assert "STUB" in context
        assert "mov eax, 1" in context
        assert FUNCTION_CODE in context
        assert "kuna" in context

    def test_function_scope_without_stored_data(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        context = conversations.build_context(conn, scope_kind="function", scope_id=function_id)
        assert "0x1000" in context
        assert "sub_1000" in context
        assert "Disassembly" not in context
        assert "Decompilation" not in context

    def test_function_scope_unknown_is_empty(self, conn: sqlite3.Connection) -> None:
        assert conversations.build_context(conn, scope_kind="function", scope_id=999) == ""

    def test_binary_scope_with_triage_and_capabilities(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, ANALYSIS)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {"count": 1, "capabilities": [{"name": "crypto", "confidence": "high"}]},
        )
        context = conversations.build_context(conn, scope_kind="binary", scope_id=binary_id)
        assert "demo.exe" in context
        assert "functions: 0" in context
        assert "Triage" in context
        assert "MSVC 6.0" in context
        assert "Capabilities" in context
        assert "crypto" in context

    def test_binary_scope_without_scans(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        context = conversations.build_context(conn, scope_kind="binary", scope_id=binary_id)
        assert "demo.exe" in context
        assert "Triage" not in context
        assert "Capabilities" not in context

    def test_binary_scope_unknown_is_empty(self, conn: sqlite3.Connection) -> None:
        assert conversations.build_context(conn, scope_kind="binary", scope_id=999) == ""

    def test_unknown_scope_kind_is_empty(self, conn: sqlite3.Connection) -> None:
        assert conversations.build_context(conn, scope_kind="galaxy", scope_id=1) == ""

    def test_context_is_bounded(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_disasm(conn, function_id, "nop\n" * (conversations.MAX_CONTEXT_CHARS * 2))
        context = conversations.build_context(conn, scope_kind="function", scope_id=function_id)
        assert len(context) == conversations.MAX_CONTEXT_CHARS
        assert context.endswith(conversations.TRUNCATION_MARKER)

    def test_default_title_uses_the_stored_rows(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        binary_id = _seed_binary(conn)
        assert (
            conversations.default_title(conn, scope_kind="function", scope_id=function_id)
            == "sub_1000 @ 0x1000"
        )
        assert (
            conversations.default_title(conn, scope_kind="binary", scope_id=binary_id) == "demo.exe"
        )
        assert conversations.default_title(conn, scope_kind="binary", scope_id=999) == "binary 999"


class TestSendMessage:
    def test_sends_system_context_and_the_new_message(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        function_id = _seed_function(conn)
        store.set_decompilation(conn, function_id, FUNCTION_CODE, "kuna")
        conversation_id = _new_conversation(conn, scope_id=function_id)
        fake_llm.response = "It returns 1."
        result = conversations.send_message(
            conn, conversation_id=conversation_id, content="what does this do?"
        )
        assert result["conversation_id"] == conversation_id
        assert result["user"]["role"] == "user"
        assert result["user"]["content"] == "what does this do?"
        assert result["assistant"]["role"] == "assistant"
        assert result["assistant"]["content"] == "It returns 1."
        assert len(fake_llm.calls) == 1
        sent = fake_llm.calls[0]
        assert [message["role"] for message in sent] == ["system", "user"]
        assert conversations.SYSTEM_PROMPT in sent[0]["content"]
        assert FUNCTION_CODE in sent[0]["content"]
        assert sent[1]["content"] == "what does this do?"
        assert fake_llm.temperatures == [llm.DEFAULT_TEMPERATURE]
        messages = store.list_messages(conn, conversation_id)
        assert [message["content"] for message in messages] == [
            "what does this do?",
            "It returns 1.",
        ]

    def test_prior_turns_are_sent_in_order(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        conversation_id = _new_conversation(conn)
        store.add_message(conn, conversation_id=conversation_id, role="user", content="prior-q")
        store.add_message(
            conn, conversation_id=conversation_id, role="assistant", content="prior-a"
        )
        conversations.send_message(conn, conversation_id=conversation_id, content="follow-up")
        assert [message["role"] for message in fake_llm.calls[0]] == [
            "system",
            "user",
            "assistant",
            "user",
        ]
        assert [message["content"] for message in fake_llm.calls[0][1:]] == [
            "prior-q",
            "prior-a",
            "follow-up",
        ]

    def test_history_is_capped_at_the_turn_limit(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        conversation_id = _new_conversation(conn)
        total = conversations.HISTORY_TURN_LIMIT + 5
        for index in range(total):
            store.add_message(
                conn, conversation_id=conversation_id, role="user", content=f"prior-{index}"
            )
        conversations.send_message(conn, conversation_id=conversation_id, content="newest")
        sent = fake_llm.calls[0]
        assert len(sent) == 1 + conversations.HISTORY_TURN_LIMIT + 1
        contents = [message["content"] for message in sent[1:]]
        assert contents[-1] == "newest"
        assert f"prior-{total - 1}" in contents
        assert f"prior-{total - conversations.HISTORY_TURN_LIMIT - 1}" not in contents

    def test_failed_request_keeps_the_user_message(self, conn: sqlite3.Connection) -> None:
        conversation_id = _new_conversation(conn)
        client = FailingLlmClient("boom")
        with pytest.raises(llm.LlmError):
            conversations.send_message(
                conn, conversation_id=conversation_id, content="will fail", client=client
            )
        messages = store.list_messages(conn, conversation_id)
        assert [message["role"] for message in messages] == ["user"]
        assert messages[0]["content"] == "will fail"

    def test_unavailable_client_raises_and_stores_no_reply(self, conn: sqlite3.Connection) -> None:
        conversation_id = _new_conversation(conn)
        with pytest.raises(llm.LlmUnavailable):
            conversations.send_message(
                conn, conversation_id=conversation_id, content="hi", client=llm.LlmClient(None)
            )
        assert [message["role"] for message in store.list_messages(conn, conversation_id)] == [
            "user"
        ]

    def test_unknown_conversation_raises_keyerror(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        with pytest.raises(KeyError):
            conversations.send_message(conn, conversation_id=999, content="hi")
        assert fake_llm.calls == []

    def test_process_client_is_the_default(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "from the process client"
        conversation_id = _new_conversation(conn)
        result = conversations.send_message(conn, conversation_id=conversation_id, content="hi")
        assert result["assistant"]["content"] == "from the process client"
        assert len(fake_llm.calls) == 1

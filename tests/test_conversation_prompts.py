"""Isolated tests for the conversation prompt boundary.

The project's pytest suite needs a venv plus the sibling engines, so these run
standalone (`python -m unittest`) and use only the store, the knowledge store
and an injected fake model client.  They pin the two prompt-boundary facts the
conversations module must keep: untrusted stored and retrieved text rides in a
user turn named ``stored_context``, never in the system prompt, and no single
message exceeds the conversation message cap.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from reportal import conversations, knowledge, llm, store


class RecordingClient(llm.LlmClient):
    """A client that records every message list it is handed."""

    def __init__(self) -> None:
        super().__init__(None)
        self.calls: list[list[dict[str, str]]] = []

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        json_object: bool = False,
        max_tokens: int = llm.MAX_COMPLETION_TOKENS,
    ) -> str:
        self.calls.append(messages)
        return "answer"

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        max_tokens: int = llm.MAX_AGENT_TOKENS,
    ) -> dict[str, Any]:
        self.calls.append(messages)
        return {"content": "answer", "tool_calls": [], "finish_reason": "stop"}


class TestAgentMessages(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "reportal.db"
        store.init_db(self.db)
        self.conn = store.connect(self.db)
        self.binary_id = store.add_binary(
            self.conn, sha256="ab" * 32, name="demo.exe", path="/x/demo.exe"
        )
        analysis_id = store.create_analysis(conn=self.conn, binary_id=self.binary_id, engine="t")
        self.function_id = store.add_function(
            self.conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16
        )
        store.set_decompilation(self.conn, self.function_id, "int f(void);", "kuna")
        self.conversation_id = store.create_conversation(
            self.conn, scope_kind="function", scope_id=self.function_id, title="chat"
        )

    def tearDown(self) -> None:
        self.conn.close()
        self._tmp.cleanup()

    def test_context_rides_in_a_user_turn_not_the_system_prompt(self) -> None:
        messages, _ = conversations.agent_messages(
            self.conn, conversation_id=self.conversation_id, content="what is this"
        )
        self.assertEqual(messages[0]["role"], "system")
        self.assertNotIn("int f(void);", messages[0]["content"])
        self.assertIn("int f(void);", messages[1]["content"])
        self.assertEqual(messages[1]["role"], "user")
        payload = json.loads(messages[1]["content"])
        self.assertIn("stored_context", payload)

    def test_the_new_message_stays_the_last_user_turn(self) -> None:
        messages, _ = conversations.agent_messages(
            self.conn, conversation_id=self.conversation_id, content="what is this"
        )
        self.assertEqual(messages[-1]["role"], "user")
        self.assertEqual(messages[-1]["content"], "what is this")

    def test_a_huge_new_message_is_bounded(self) -> None:
        messages, _ = conversations.agent_messages(
            self.conn,
            conversation_id=self.conversation_id,
            content="A" * (conversations.MAX_MESSAGE_CHARS * 2),
        )
        self.assertLessEqual(len(messages[-1]["content"]), conversations.MAX_MESSAGE_CHARS)
        self.assertTrue(messages[-1]["content"].endswith("...[truncated]"))

    def test_a_huge_history_turn_is_bounded(self) -> None:
        store.add_message(
            self.conn,
            conversation_id=self.conversation_id,
            role="user",
            content="B" * (conversations.MAX_MESSAGE_CHARS * 2),
        )
        client = RecordingClient()
        conversations.send_message(
            self.conn, conversation_id=self.conversation_id, content="next", client=client
        )
        sent = client.calls[0]
        history = sent[2:-1]
        bounded = [m for m in history if m["content"].startswith("B")]
        self.assertEqual(len(bounded), 1)
        self.assertLessEqual(len(bounded[0]["content"]), conversations.MAX_MESSAGE_CHARS)

    def test_retrieved_documents_ride_in_the_stored_context_turn(self) -> None:
        knowledge.ingest_document(
            self.conn,
            scope_kind=knowledge.SCOPE_KIND_BINARY,
            scope_id=self.binary_id,
            title="notes",
            source="notes.md",
            mime="text/markdown",
            data=b"The timer callback arms the watchdog.",
        )
        messages, sources = conversations.agent_messages(
            self.conn, conversation_id=self.conversation_id, content="timer callback"
        )
        self.assertTrue(sources)
        payload = json.loads(messages[1]["content"])
        self.assertIn("timer callback arms the watchdog", payload["stored_context"])
        self.assertNotIn("timer callback arms the watchdog", messages[0]["content"])

    def test_send_message_uses_the_same_assembly(self) -> None:
        client = RecordingClient()
        result = conversations.send_message(
            self.conn, conversation_id=self.conversation_id, content="what is this", client=client
        )
        self.assertEqual(result["assistant"]["content"], "answer")
        sent = client.calls[0]
        self.assertEqual(sent[0]["role"], "system")
        self.assertNotIn("int f(void);", sent[0]["content"])
        self.assertIn("int f(void);", sent[1]["content"])


if __name__ == "__main__":
    unittest.main()

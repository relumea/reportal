"""A tenant sees the answer, never the machinery that produced it.

Which model ran, how long it deliberated and what it called are operating
details: a commercial position and a probing surface, not part of what is sold.
These tests are the regression that keeps a future payload from quietly
disclosing them, which is easy to do by accident because every producer has the
model name in hand when it builds its result.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from conftest import json_body, on_request

from reportal import auth, disclosure, store

TENANT = {"role": "analyst", "name": "customer"}
VIEWER = {"role": "viewer", "name": "customer"}
ADMIN = {"role": "admin", "name": "operator"}


class TestWhoIsAnOperator:
    """The exemption, and how narrow it is."""

    def test_an_admin_is_an_operator(self) -> None:
        assert disclosure.is_operator(ADMIN) is True

    def test_a_tenant_user_is_not(self) -> None:
        """An analyst is a customer's user, not ours."""
        assert disclosure.is_operator(TENANT) is False
        assert disclosure.is_operator(VIEWER) is False

    def test_no_caller_is_the_local_operator(self) -> None:
        """Auth off means one person on loopback; there is no tenant to hide from."""
        assert disclosure.is_operator(None) is True


class TestRedaction:
    """What comes out of a payload bound for a tenant."""

    def test_the_model_name_is_removed(self) -> None:
        payload = {"summary": "parses a header", "model": "deepseek-flash"}
        assert disclosure.redact_payload(payload, caller=TENANT) == {"summary": "parses a header"}

    def test_token_counts_are_removed(self) -> None:
        """A tenant is billed in credits; token counts are the internal read."""
        payload = {
            "code": "int f(void);",
            "prompt_tokens": 400,
            "completion_tokens": 5976,
            "reasoning_tokens": 5692,
            "usage": {"total_tokens": 6376},
        }
        assert disclosure.redact_payload(payload, caller=TENANT) == {"code": "int f(void);"}

    def test_redaction_reaches_nested_payloads(self) -> None:
        """A field nobody remembered to strip is stripped anyway."""
        payload = {
            "suggestions": [{"name": "parse_header", "model": "deepseek-flash", "confidence": 0.9}],
            "nested": {"deep": {"model": "deepseek-flash", "kept": 1}},
        }
        redacted = disclosure.redact_payload(payload, caller=TENANT)
        assert redacted == {
            "suggestions": [{"name": "parse_header", "confidence": 0.9}],
            "nested": {"deep": {"kept": 1}},
        }

    def test_the_prompt_is_never_returned(self) -> None:
        """The prompt shape is the product; a caller must not be able to read it."""
        payload = {"answer": "ok", "system_prompt": "You are...", "messages": [{"role": "user"}]}
        assert disclosure.redact_payload(payload, caller=TENANT) == {"answer": "ok"}

    def test_an_operator_sees_everything(self) -> None:
        payload = {"summary": "x", "model": "deepseek-flash", "prompt_tokens": 400}
        assert disclosure.redact_payload(payload, caller=ADMIN) == payload

    def test_the_local_operator_sees_everything(self) -> None:
        payload = {"summary": "x", "model": "deepseek-flash"}
        assert disclosure.redact_payload(payload, caller=None) == payload

    def test_an_own_engine_name_is_disclosed_when_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Once the model is ours it is a feature, so the seam can name it."""
        monkeypatch.setattr(disclosure, "PUBLIC_ENGINE_NAME", "reportal-sk2")
        payload = {"summary": "x", "model": "deepseek-flash"}
        assert disclosure.redact_payload(payload, caller=TENANT) == {
            "summary": "x",
            "model": "reportal-sk2",
        }

    def test_nothing_is_claimed_while_the_backend_is_a_supplier(self) -> None:
        """The default omits rather than invents: a made-up name is a claim."""
        assert disclosure.PUBLIC_ENGINE_NAME == ""

    def test_a_list_payload_is_redacted(self) -> None:
        payload = [{"model": "deepseek-flash", "name": "a"}, {"name": "b"}]
        assert disclosure.redact_payload(payload, caller=TENANT) == [{"name": "a"}, {"name": "b"}]

    def test_values_that_are_not_containers_pass_through(self) -> None:
        assert disclosure.redact_payload(42, caller=TENANT) == 42
        assert disclosure.redact_payload(None, caller=TENANT) is None


class TestReasoningNeverReachesText:
    """Free text is the one path with no JSON parser to strip markup."""

    def test_a_thinking_block_is_removed(self) -> None:
        text = "<thinking>the user wants X, so I will</thinking>It parses a header."
        assert disclosure.clean_text(text) == "It parses a header."

    def test_every_spelling_of_the_block_is_removed(self) -> None:
        for open_tag, close_tag in (
            ("<think>", "</think>"),
            ("<reasoning>", "</reasoning>"),
            ("<tool_call>", "</tool_call>"),
            ("<tool_calls>", "</tool_calls>"),
        ):
            text = f"{open_tag}hidden{close_tag}visible"
            assert disclosure.clean_text(text) == "visible", open_tag

    def test_a_thought_line_is_removed(self) -> None:
        assert disclosure.clean_text("Thought: I should check\nThe answer.") == "The answer."

    def test_an_unterminated_tag_does_not_swallow_the_answer(self) -> None:
        """A truncated block must lose the tag, never the text after it."""
        assert "42" in disclosure.clean_text("<think>oops The answer is 42.")

    def test_ordinary_prose_survives(self) -> None:
        """The removal is bounded to markup, not to words."""
        text = "The function does no reasoning about its input and calls no tools."
        assert disclosure.clean_text(text) == text

    def test_redaction_cleans_strings_it_passes(self) -> None:
        payload = {"summary": "<thinking>hmm</thinking>It frees the buffer."}
        assert disclosure.redact_payload(payload, caller=TENANT) == {
            "summary": "It frees the buffer."
        }

    def test_artifact_code_is_not_rewritten(self) -> None:
        """Stored source may contain the same markup shapes as model prose."""
        code = 'char *s = "<thinking>x</thinking>";'
        payload = {"code": code, "model": "deepseek-flash"}
        assert disclosure.redact_payload(payload, caller=TENANT) == {"code": code}


class TestTheRouteSurface:
    """The seam is the response, so a route cannot opt out by forgetting."""

    def test_a_tenant_request_is_redacted_end_to_end(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With auth on, an analyst's own read must not name the backend model.

        This is the whole point of the seam, so it is exercised through a real
        request with a real token rather than by calling the helper directly.
        """
        monkeypatch.setenv("REPORTAL_LLM_ENDPOINT", "https://example.invalid")
        monkeypatch.setenv("REPORTAL_LLM_MODEL", "deepseek-flash")
        with contextlib.closing(store.connect(portal_db)) as conn:
            _, analyst_token = auth.add_user(conn, name="tenant", role=auth.ROLE_ANALYST)
            _, admin_token = auth.add_user(conn, name="operator", role=auth.ROLE_ADMIN)
            conn.commit()
        monkeypatch.setenv("REPORTAL_AUTH", "1")

        _, _, chunks = on_request(
            "GET", "/api/config", headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert b"deepseek-flash" not in b"".join(chunks)

        # The same read as an operator still carries it, or the exemption is
        # not working and the cost and debugging paths would be blind.
        _, _, chunks = on_request(
            "GET", "/api/config", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert b"deepseek-flash" in b"".join(chunks)

    def test_the_plans_route_never_names_a_backend(self, portal_db: Path) -> None:
        """The price list is public, so it must never disclose the supplier."""
        _, _, chunks = on_request("GET", "/api/plans")
        rendered = json.dumps(json_body(b"".join(chunks), {})).lower()
        for vendor in ("deepseek", "claude", "sonnet", "gpt-", "anthropic", "openai"):
            assert vendor not in rendered, vendor

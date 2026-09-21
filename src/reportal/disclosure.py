"""What a tenant is allowed to see about how an answer was produced.

reportal sells the answer, not the machinery.  Which engine produced a
decompilation, which model produced an AI artifact, how long it deliberated
and which tools it called are operating details: they are a commercial
position (the backend is a supplier choice that changes without notice) and
they are a security surface (a caller who knows the exact model and prompt
shape can probe them).  A customer gets the artifact and
the price; an operator gets everything.

This module is the one place that decides.  Two rules, applied at the edge:

* :func:`redact_payload` removes the internal keys from anything a tenant
  receives.  It runs on the assembled response rather than at each producer, so
  a new AI artifact is private by construction: a field nobody remembered to
  strip is stripped anyway, which is the failure mode a per-producer rule has.
* :func:`clean_text` removes reasoning and tool-call markup from free text.
  The JSON artifacts already pass through :func:`reportal.llm._parse_json`,
  which strips it before parsing; the agent's final answer does not, because it
  is returned as prose, so that path is cleaned here.  Only keys in
  :data:`PROSE_KEYS` are cleaned: stored source, paths and similar artifact
  strings must stay byte-for-byte.

Operators are exempt.  An admin debugging a bad artifact needs to know which
backend produced it, the usage ledger needs the model to price a row, and
``tools/bench_credits.py`` needs it to compare models at all.  The exemption is
a role check rather than a separate route, so there is one implementation of
the payload and only the audience differs.

Later, when the model *is* the product (a decompilation-specific model of our
own), the decision to disclose becomes a product choice rather than a leak.
:data:`PUBLIC_ENGINE_NAME` is where that name goes, and until it is set a tenant
simply sees no model field at all.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from reportal import auth

# Keys a tenant never receives from any payload.  `model` names the
# supplier, the token counts expose the deliberation the credit price already
# accounts for, and the reasoning fields are the machinery itself.
# `rebrew_project` is a server-local working directory, and `origin` a
# server-local install path: neither means anything to a platform caller.
# The model registry (`/api/models`) keeps its internal names; tenants never
# call it because the customer CLI exposes no model command.
INTERNAL_KEYS: frozenset[str] = frozenset(
    {
        "model",
        "models",
        "backend_model",
        "rebrew_project",
        "origin",
        "prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "total_tokens",
        "usage",
        "thinking",
        "reasoning",
        "reasoning_content",
        "thinking_ratio",
        "endpoint",
        "provider",
        "system_prompt",
        "prompt",
        "messages",
    }
)

# What a tenant is told produced an answer, once there is something worth
# naming.  Empty means the field is omitted entirely, which is the honest
# default while the backend is a third-party model: a made-up name would be a
# claim rather than a redaction.
PUBLIC_ENGINE_NAME = ""

# Free-text keys an agent or summary may put prose in.  ``clean_text`` runs on
# these only: applying it to every string would rewrite stored source, paths,
# and binary string literals that happen to contain the same markup shapes.
PROSE_KEYS: frozenset[str] = frozenset(
    {
        "answer",
        "summary",
        "content",
        "message",
        "explanation",
        "comment",
        "notes",
        "description",
        "body",
        "note",
    }
)

# Reasoning and tool-call markup a model may emit inline.  The same literals
# `llm._strip_reasoning` removes before parsing JSON, applied here to the free
# text that never goes through a parser.
_BLOCKS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<thinking>.*?</thinking>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<reasoning>.*?</reasoning>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<tool_calls?>.*?</tool_calls?>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<\|thinking\|>.*?<\|/thinking\|>", re.DOTALL | re.IGNORECASE),
)
_STRAY_TAG = re.compile(
    r"</?(?:thinking|think|reasoning|tool_calls?)\s*>|<\|/?thinking\|>", re.IGNORECASE
)
_THOUGHT_LINE = re.compile(r"^[ \t]*(?:Thought|Reasoning)\s*:.*$", re.MULTILINE | re.IGNORECASE)


def is_operator(caller: Mapping[str, Any] | None) -> bool:
    """Whether *caller* may see the machinery.

    None is the local operator: auth is off, so the install is one person on
    loopback and there is no tenant to keep anything from.  With auth on, only
    an admin qualifies, because an analyst is a customer's user.
    """
    if caller is None:
        return True
    return str(caller.get("role") or "") == auth.ROLE_ADMIN


def clean_text(text: str) -> str:
    """Strip reasoning and tool-call markup from free text.

    A balanced block goes whole; a stray or unterminated tag loses only the tag,
    so an unclosed ``<thinking>`` cannot swallow the answer that follows it.
    """
    cleaned = text
    for pattern in _BLOCKS:
        cleaned = pattern.sub(" ", cleaned)
    cleaned = _STRAY_TAG.sub(" ", cleaned)
    cleaned = _THOUGHT_LINE.sub("", cleaned)
    return re.sub(r"\n{3,}", "\n\n", cleaned).strip()


def redact_payload(payload: Any, *, caller: Mapping[str, Any] | None = None) -> Any:
    """Remove internal keys from *payload*, unless the caller is an operator.

    Applied to the whole response, at any depth, so a nested artifact is covered
    without naming every shape.  When :data:`PUBLIC_ENGINE_NAME` is set, a
    removed ``model`` is replaced by it rather than dropped, which is how an
    own model becomes visible without every producer changing.
    """
    if is_operator(caller):
        return payload
    return _redact(payload)


def _redact(value: Any) -> Any:
    """The recursive half of :func:`redact_payload`."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in INTERNAL_KEYS:
                if key == "model" and PUBLIC_ENGINE_NAME:
                    result[key] = PUBLIC_ENGINE_NAME
                continue
            if key in PROSE_KEYS and isinstance(item, str):
                result[key] = clean_text(item)
            else:
                result[key] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value

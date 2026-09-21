# Conversations, comments and analyst strings

Sources: src/reportal/conversations.py, src/reportal/agent.py, src/reportal/comments.py, src/reportal/user_strings.py

This subsystem owns what the analyst says rather than what an engine found: scoped chat threads,
agent runs over the MCP registry, free-text comments and analyst strings. A read runs nothing:
`build_context` reads rows the workspace already holds, an unconfigured bridge raises
`LlmUnavailable`, and every write is journaled so one action reverts as one entry.

## Vocabulary

- `conversations.SCOPE_KINDS`: `function`, `binary` and `docs`. `SCOPE_KIND_DOCS` grounds a chat in
  the in-app manual through `docs`.
- `conversations.MAX_CONTEXT_CHARS` (4000), `MAX_MESSAGE_CHARS` and `HISTORY_TURN_LIMIT` (10) bound
  one turn. Retrieved documents are appended last, so truncation hits them first.
- `agent.RUN_TABLE` (`conversation_runs`) statuses: `running`, `waiting_confirmation`, `completed`,
  `cancelled`, `failed`. `MAX_TOOL_CALLS` (8), `MAX_TOOL_RESULT_CHARS`, `MAX_ARGUMENT_CHARS` and
  `MAX_EVENTS` bound a run.
- `comments.SCOPE_KINDS` is only `binary` and `function`; `MAX_COMMENT_CHARS` is 4000 and
  `DEFAULT_AUTHOR` is `analyst`.
- `user_strings.TABLE` (`user_strings`) holds one value per row at `function` or `analysis` scope
  with a kind and a note. `MAX_STRINGS_PER_SCOPE` is 500. A function's read keeps three labelled
  halves apart: stored rows, `derived_literals` and `decoded_strings`.

## Wiring

- Routes: `GET`/`POST /api/conversations`, `GET`/`DELETE /api/conversations/<id>`, `POST
  .../messages`, `POST .../runs`, `GET .../runs/<run_id>`, `POST .../confirm`, `POST .../cancel`,
  `GET .../events`; `GET`/`POST /api/binaries/<id>/comments`, `GET`/`POST
  /api/functions/<id>/comments`, `PATCH`/`DELETE /api/comments/<id>`; `GET`/`POST
  /api/functions/<id>/strings`, `DELETE .../strings/<string_id>`, `GET`/`POST
  /api/analyses/<id>/strings`, `PUT /api/analyses/<id>/strings`.
- CLI: `conversations`, `conversation-run`, `conversation-runs`, `conversation-run-status`,
  `conversation-confirm`, `conversation-cancel`, `conversation-events`, `comments`, `comment-add`,
  `comment-rm`, `function-strings`, `user-string-add`, `user-string-rm`, `analysis-strings`,
  `analysis-strings-set`.
- MCP: `list_conversations`, `create_conversation`, `get_conversation`, `send_conversation_message`,
  `run_conversation_agent`, `get_conversation_run`, `confirm_conversation_run`,
  `cancel_conversation_run`, `add_comment`, `update_comment`, `delete_comment`,
  `add_function_string`.
- Tables: `conversations`, `messages`, `conversation_runs`, `comments`, `user_strings` (own schema
  in `agent.ensure_schema` and `user_strings.ensure_schema`).

## Invariants

- A tool the registry does not declare counts as destructive, so the run pauses at
  `waiting_confirmation`. `tests/test_agent.py`.
- A read-only tool runs through `mcp_server.call_tool`; a rejected call is fed back as a refused
  result, never retried. `tests/test_agent.py`.
- The loop re-reads its own row before each step, so a cancel lands at the next step boundary.
  `tests/test_agent.py`.
- `replace_strings` validates every value before writing, and a revert restores the previous list
  whether it held rows or was empty. `tests/test_user_strings.py`.
- An unsupported comment scope is `invalid comment`; an unknown scope id is not-found.
  `tests/test_comments.py`.

## See also

- [ARCHITECTURE.md, Agent runs](../ARCHITECTURE.md#agent-runs)
- [ARCHITECTURE.md, LLM bridge](../ARCHITECTURE.md#llm-bridge)
- [API.md](../API.md)

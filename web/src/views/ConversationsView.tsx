import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  Toolbar,
} from "../components";
import { CONVERSATION_SCOPE_KINDS } from "../constants";
import type { ConversationScopeKind } from "../constants";
import type {
  AgentRunEvent,
  AgentRunList,
  Conversation,
  ConversationMessage,
  ConversationReply,
  ConversationThread,
  KnowledgeHit,
} from "../types";
import { useAsync } from "../useAsync";

const AGENT_TERMINAL = ["completed", "cancelled", "failed"];

/** One agent run's event as a single line of text. */
function eventLabel(event: AgentRunEvent): string {
  switch (event.kind) {
    case "run-started":
      return "started";
    case "tool-call":
      return `tool ${event.tool ?? ""}${event.failed ? " (failed)" : ""}`;
    case "tool-rejected":
      return `rejected ${event.tool ?? ""}`;
    case "confirmation-required":
      return `confirmation required: ${event.name ?? ""}`;
    case "assistant-message":
      return "answered";
    case "run-cancelled":
      return "cancelled";
    case "run-failed":
      return `failed: ${event.detail ?? ""}`;
    case "tool-limit":
      return "tool-call limit reached";
    default:
      return event.kind;
  }
}

/**
 * The agent half of a conversation: one tool loop per run.
 *
 * A read-only tool runs during the request; a destructive one pauses the run,
 * and the analyst approves or rejects the exact call here.  The run's state
 * streams over `GET /api/conversations/<id>/events` for a client that wants
 * live updates; this panel refreshes on demand and after every action.
 */
function AgentPanel({ conversationId }: { conversationId: number }): ReactNode {
  const { data, error, reload } = useAsync(
    () =>
      api<AgentRunList>(`/conversations/${conversationId}/runs`).catch(() => ({
        conversation_id: conversationId,
        runs: [],
        count: 0,
      })),
    [conversationId],
  );
  const [draft, setDraft] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const run = data?.runs[0];

  const act = async (path: string, body: Record<string, unknown>, tag: string): Promise<void> => {
    setBusy(tag);
    setActionError(null);
    try {
      await api(path, { method: "POST", json: body });
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const start = async (): Promise<void> => {
    const content = draft.trim();
    if (!content) return;
    await act(`/conversations/${conversationId}/runs`, { content }, "start");
    setDraft("");
  };

  return (
    <Panel
      title="Agent run"
      subtitle="The model may call this portal's own tools. A read-only tool runs at once; a tool that changes the workspace waits for your approval."
      actions={
        <Button size="sm" tone="ghost" onClick={reload}>
          Refresh
        </Button>
      }
    >
      <form
        className="toolbar"
        onSubmit={(event) => {
          event.preventDefault();
          void start();
        }}
      >
        <textarea
          className="chat-input"
          aria-label="Agent question"
          placeholder="Ask the agent to work with this context"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
        <Button tone="primary" type="submit" pending={busy === "start"} disabled={!draft.trim()}>
          Run agent
        </Button>
      </form>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {!run ? (
        <EmptyState>No agent run yet. Ask a question in the box above.</EmptyState>
      ) : (
        <>
          <Muted>
            run {run.run_id}: {run.status} ({run.tool_calls} tool call(s))
            {run.live ? ", live" : ""}
          </Muted>
          <ol className="list">
            {run.events.map((event, index) => (
              <li key={`${event.at}-${index}`}>
                <span className="mono">{event.at}</span> {eventLabel(event)}
              </li>
            ))}
          </ol>
          {run.pending ? (
            <div className="stack">
              <Muted>
                Pending call: <span className="mono">{run.pending.name}</span>{" "}
                {JSON.stringify(run.pending.arguments)}
              </Muted>
              <Toolbar>
                <Button
                  tone="primary"
                  pending={busy === "approve"}
                  onClick={() =>
                    void act(
                      `/conversations/${conversationId}/confirm`,
                      { approve: true, run_id: run.run_id },
                      "approve",
                    )
                  }
                >
                  Approve call
                </Button>
                <Button
                  pending={busy === "reject"}
                  onClick={() =>
                    void act(
                      `/conversations/${conversationId}/confirm`,
                      { approve: false, run_id: run.run_id },
                      "reject",
                    )
                  }
                >
                  Reject call
                </Button>
              </Toolbar>
            </div>
          ) : null}
          {run.live ? (
            <Toolbar>
              <Button
                size="sm"
                tone="ghost"
                pending={busy === "cancel"}
                onClick={() =>
                  void act(
                    `/conversations/${conversationId}/cancel`,
                    { run_id: run.run_id },
                    "cancel",
                  )
                }
              >
                Cancel run
              </Button>
            </Toolbar>
          ) : null}
          {run.content ? (
            <div className="message">
              <div className="message-role">agent</div>
              <p className="message-body">{run.content}</p>
            </div>
          ) : null}
          {run.error ? <ErrorNote error={new Error(run.error)} /> : null}
          {AGENT_TERMINAL.includes(run.status) && !run.content && !run.error ? (
            <Muted>The run finished without an answer.</Muted>
          ) : null}
        </>
      )}
    </Panel>
  );
}

const SCOPE_HINTS: Record<ConversationScopeKind, string> = {
  function: "Function id",
  binary: "Binary id",
  docs: "Documentation (the id is ignored)",
};

/** The canned prompts a conversation offers, by scope.  The hosted portal's
 * assistant changes its prompt library with the page context; this is the local
 * version of that: a few openers that fit what the scope can actually answer,
 * and no prompt that names a capability the scope does not have. */
const SCOPE_PROMPTS: Record<ConversationScopeKind, readonly string[]> = {
  docs: [
    "How do I add a binary and run an analysis?",
    "Which error codes can a route return?",
    "What is deliberately not implemented?",
    "How does the knowledge graph work?",
  ],
  binary: [
    "What does this binary import that looks risky?",
    "Summarize the stored triage result.",
    "Which capabilities were tagged and why?",
  ],
  function: [
    "What does this function do?",
    "Which strings and calls does it use?",
    "Suggest a name for it.",
  ],
};

/** The citations a reply was grounded in, as a small disclosure. */
function SourceList({ sources }: { sources: KnowledgeHit[] }): ReactNode {
  if (!sources.length) return null;
  return (
    <details className="sources">
      <summary>Sources ({sources.length})</summary>
      <ul>
        {sources.map((source, index) => (
          <li key={`${source.document_id}:${source.chunk_id}`}>
            <span className="mono">[{index + 1}]</span> {source.title} ({source.source}) ·{" "}
            {Number(source.score).toFixed(4)} {source.method}
          </li>
        ))}
      </ul>
    </details>
  );
}

function MessageList({
  messages,
  sources,
  replyId,
}: {
  messages: ConversationMessage[];
  sources: KnowledgeHit[];
  replyId: number | null;
}): ReactNode {
  if (!messages.length) {
    return <EmptyState>No messages yet. Ask the first question in the box below.</EmptyState>;
  }
  return (
    <div className="messages">
      {messages.map((message) => (
        <div className="message" key={message.id}>
          <div className="message-role">{message.role}</div>
          <p className="message-body">{message.content}</p>
          {message.id === replyId ? <SourceList sources={sources} /> : null}
        </div>
      ))}
    </div>
  );
}

/** Chat list: create a conversation for a scope, open or delete one. */
export function ConversationsView(): ReactNode {
  const navigate = useNavigate();
  const { data, error, reload } = useAsync(
    () => api<{ conversations: Conversation[] }>("/conversations"),
    [],
  );
  const [scopeKind, setScopeKind] = useState<ConversationScopeKind>("function");
  const [scopeId, setScopeId] = useState("");
  const [title, setTitle] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const create = async (): Promise<void> => {
    setActionError(null);
    setBusy("create");
    try {
      const conversation = await api<Conversation>("/conversations", {
        method: "POST",
        json: { scope_kind: scopeKind, scope_id: Number(scopeId), title },
      });
      setScopeId("");
      setTitle("");
      navigate(`/conversations/${conversation.id}`);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (id: number): Promise<void> => {
    setActionError(null);
    setBusy(`delete-${id}`);
    try {
      await api(`/conversations/${id}`, { method: "DELETE" });
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const conversations = data?.conversations;

  return (
    <Panel
      title="Conversations"
      subtitle="Threads grounded in the portal's stored knowledge for one function or binary."
      actions={
        <Button
          tone="primary"
          pending={busy === "create"}
          disabled={!scopeId.trim()}
          onClick={() => void create()}
        >
          Create
        </Button>
      }
    >
      <Toolbar>
        <Field label="Scope">
          <select
            value={scopeKind}
            onChange={(event) =>
              setScopeKind(event.target.value === "binary" ? "binary" : "function")
            }
          >
            {CONVERSATION_SCOPE_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        </Field>
        <Field label={SCOPE_HINTS[scopeKind]}>
          <input
            placeholder={SCOPE_HINTS[scopeKind]}
            value={scopeId}
            onChange={(event) => setScopeId(event.target.value)}
          />
        </Field>
        <Field label="Title">
          <input
            placeholder="optional"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
        </Field>
      </Toolbar>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {conversations === undefined ? (
        <Loading label="Loading conversations" />
      ) : (
        <DataTable
          columns={[
            { label: "ID", key: "id", numeric: true },
            { label: "Title", key: "title" },
            { label: "Scope", render: (row) => `${row.scope_kind} ${row.scope_id}` },
            { label: "Messages", key: "message_count", numeric: true },
            { label: "Created", key: "created_at", mono: true },
            {
              label: "Actions",
              render: (row) => (
                <div className="actions-cell">
                  <Button size="sm" onClick={() => navigate(`/conversations/${row.id}`)}>
                    Open
                  </Button>
                  <ConfirmButton
                    label="Delete"
                    message="Delete chat?"
                    pending={busy === `delete-${row.id}`}
                    onConfirm={() => void remove(row.id)}
                  />
                </div>
              ),
            },
          ]}
          rows={conversations}
          rowKey={(row) => row.id}
          onRowClick={(row) => navigate(`/conversations/${row.id}`)}
          empty={
            <EmptyState>
              No conversations yet. Create one for a function or binary from the fields above.
            </EmptyState>
          }
        />
      )}
    </Panel>
  );
}

/** One conversation thread: its messages, a composer and a delete control. */
export function ConversationDetail({ conversationId }: { conversationId: number }): ReactNode {
  const navigate = useNavigate();
  const { data, error, reload } = useAsync(
    () => api<ConversationThread>(`/conversations/${conversationId}`),
    [conversationId],
  );
  const [draft, setDraft] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [sending, setSending] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [sources, setSources] = useState<KnowledgeHit[]>([]);
  const [replyId, setReplyId] = useState<number | null>(null);

  useEffect(() => {
    setSources([]);
    setReplyId(null);
  }, [conversationId]);

  const send = async (): Promise<void> => {
    const content = draft.trim();
    if (!content) return;
    setSending(true);
    setActionError(null);
    try {
      const reply = await api<ConversationReply>(`/conversations/${conversationId}/messages`, {
        method: "POST",
        json: { content },
      });
      setDraft("");
      setSources(reply.sources ?? []);
      setReplyId(reply.assistant.id);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setSending(false);
    }
  };

  const remove = async (): Promise<void> => {
    setActionError(null);
    setRemoving(true);
    try {
      await api(`/conversations/${conversationId}`, { method: "DELETE" });
      navigate("/conversations");
    } catch (failure) {
      setActionError(failure);
    } finally {
      setRemoving(false);
    }
  };

  if (error) return <ErrorNote error={error} onRetry={reload} />;
  if (!data) {
    return (
      <Panel title="Conversation">
        <Loading label="Loading the conversation" />
      </Panel>
    );
  }

  return (
    <Panel
      title={data.title}
      subtitle={`${data.scope_kind} ${data.scope_id} · created ${data.created_at}`}
      actions={
        <>
          <a className="back-link" href="#/conversations">
            Back to conversations
          </a>
          <ConfirmButton
            label="Delete"
            message="Delete chat?"
            pending={removing}
            onConfirm={() => void remove()}
          />
        </>
      }
    >
      <MessageList messages={data.messages} sources={sources} replyId={replyId} />
      <AgentPanel conversationId={conversationId} />
      <form
        className="toolbar"
        onSubmit={(event) => {
          event.preventDefault();
          void send();
        }}
      >
        <textarea
          className="chat-input"
          aria-label="Message"
          placeholder="Ask about this context"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
        />
        <Button tone="primary" type="submit" pending={sending} disabled={!draft.trim()}>
          Send
        </Button>
      </form>
      <div className="prompt-library" aria-label="Suggested prompts">
        {SCOPE_PROMPTS[data.scope_kind as ConversationScopeKind]?.map((prompt) => (
          <Button key={prompt} size="sm" tone="ghost" onClick={() => setDraft(prompt)}>
            {prompt}
          </Button>
        ))}
      </div>
      {actionError ? <ErrorNote error={actionError} /> : null}
    </Panel>
  );
}

/** Start a conversation for a scope and open it. */
export function ChatAboutButton({
  scopeKind,
  scopeId,
}: {
  scopeKind: ConversationScopeKind;
  scopeId: number;
}): ReactNode {
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const start = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const conversation = await api<Conversation>("/conversations", {
        method: "POST",
        json: { scope_kind: scopeKind, scope_id: scopeId },
      });
      navigate(`/conversations/${conversation.id}`);
    } catch (failure) {
      setError(failure);
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <Toolbar>
        <Button tone="primary" pending={busy} onClick={() => void start()}>
          Chat about this
        </Button>
        <Muted>Opens a new conversation scoped to this {scopeKind}.</Muted>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
    </div>
  );
}

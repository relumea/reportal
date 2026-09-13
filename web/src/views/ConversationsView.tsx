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
  Conversation,
  ConversationMessage,
  ConversationReply,
  ConversationThread,
  KnowledgeHit,
} from "../types";
import { useAsync } from "../useAsync";

const SCOPE_HINTS: Record<ConversationScopeKind, string> = {
  function: "Function id",
  binary: "Binary id",
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

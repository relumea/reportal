import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  ConfirmButton,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  Toolbar,
} from "../components";
import {
  COMMENT_AUTHOR_STORAGE_KEY,
  COMMENT_MAX_CHARS,
  DEFAULT_COMMENT_AUTHOR,
} from "../constants";
import type { CommentScopeKind } from "../constants";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type { Comment, CommentList, Me } from "../types";
import { useAsync } from "../useAsync";

function scopePath(scopeKind: CommentScopeKind, scopeId: number): string {
  return scopeKind === "binary" ? `/binaries/${scopeId}/comments` : `/functions/${scopeId}/comments`;
}

/** The author this browser last commented as, so edit and delete stay its own. */
function loadAuthor(): string {
  try {
    return window.localStorage.getItem(COMMENT_AUTHOR_STORAGE_KEY)?.trim() || DEFAULT_COMMENT_AUTHOR;
  } catch {
    // Storage can be unavailable (private mode); the default author still works.
    return DEFAULT_COMMENT_AUTHOR;
  }
}

function storeAuthor(author: string): void {
  try {
    window.localStorage.setItem(COMMENT_AUTHOR_STORAGE_KEY, author);
  } catch {
    // A refused write only loses the remembered name, never the comment.
  }
}

function clearStoredAuthor(): void {
  try {
    window.localStorage.removeItem(COMMENT_AUTHOR_STORAGE_KEY);
  } catch {
    // Private mode: nothing to clear.
  }
}

function isEdited(comment: Comment): boolean {
  return comment.updated_at !== comment.created_at;
}

/** Analyst comments of one binary or function, with add, edit and delete. */
export function CommentsPanel({
  scopeKind,
  scopeId,
}: {
  scopeKind: CommentScopeKind;
  scopeId: number;
}): ReactNode {
  const path = scopePath(scopeKind, scopeId);
  const key = panelKey(scopeKind, scopeId, "comments");
  const load = (): Promise<CommentList> => api<CommentList>(path);
  const entry = usePanel<CommentList>(key, load);
  const me = useAsync(() => api<Me>("/iam/me"), []);
  const authRequired = me.data?.auth === "required";
  const callerName = me.data?.user?.name ?? "";
  const callerId = me.data?.user?.id ?? null;
  const [author, setAuthor] = useState(loadAuthor);
  const [text, setText] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  const [draft, setDraft] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    if (!authRequired || !callerName) return;
    setAuthor(callerName);
    clearStoredAuthor();
  }, [authRequired, callerName]);

  const refresh = (): void => refreshPanel(key, load);

  const rememberAuthor = (value: string): void => {
    setAuthor(value);
    storeAuthor(value);
  };

  const ownsComment = (comment: Comment): boolean => {
    if (authRequired && callerId != null && comment.author_user_id != null) {
      return comment.author_user_id === callerId;
    }
    return comment.author === author;
  };

  const add = async (): Promise<void> => {
    setActionError(null);
    const body = text.trim();
    if (!body) return;
    setBusy("add");
    try {
      // With token auth the server attributes the comment to the caller; the
      // freeform author field is only for the auth-off local operator.
      const json = authRequired ? { body } : { body, author };
      await api(path, { method: "POST", json });
      setText("");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const save = async (commentId: number): Promise<void> => {
    setActionError(null);
    const body = draft.trim();
    if (!body) return;
    setBusy(`save-${commentId}`);
    try {
      await api(`/comments/${commentId}`, { method: "PATCH", json: { body } });
      setEditing(null);
      setDraft("");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (commentId: number): Promise<void> => {
    setActionError(null);
    setBusy(`remove-${commentId}`);
    try {
      await api(`/comments/${commentId}`, { method: "DELETE" });
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Comments"
      subtitle="Analyst notes stored with this scope; only your own comments can be edited."
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void add();
        }}
      >
        <Toolbar>
          {authRequired ? null : (
            <Field label="Author">
              <input
                value={author}
                onChange={(event) => rememberAuthor(event.target.value)}
                placeholder={DEFAULT_COMMENT_AUTHOR}
              />
            </Field>
          )}
          <Button tone="primary" type="submit" pending={busy === "add"}>
            Add comment
          </Button>
        </Toolbar>
        <textarea
          className="chat-input"
          aria-label="New comment"
          value={text}
          maxLength={COMMENT_MAX_CHARS}
          onChange={(event) => setText(event.target.value)}
          placeholder="Add an analyst comment"
        />
      </form>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {!entry || entry.state === "loading" ? (
        <Loading label="Loading comments" />
      ) : entry.state === "error" ? (
        <ErrorNote error={entry.error} onRetry={refresh} />
      ) : entry.data.comments.length === 0 ? (
        <EmptyState>No comments yet. Write the first one in the box above.</EmptyState>
      ) : (
        <div className="messages">
          {entry.data.comments.map((comment) => (
            <div className="message" key={comment.id}>
              <div className="message-head">
                <span className="message-author">{comment.author}</span>
                <span className="muted">
                  {comment.created_at}
                  {isEdited(comment) ? ` (edited ${comment.updated_at})` : ""}
                </span>
                {ownsComment(comment) ? (
                  <span className="message-actions">
                    {editing === comment.id ? (
                      <>
                        <Button size="sm" pending={busy === `save-${comment.id}`} onClick={() => void save(comment.id)}>
                          Save
                        </Button>
                        <Button
                          size="sm"
                          tone="ghost"
                          onClick={() => {
                            setEditing(null);
                            setDraft("");
                          }}
                        >
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          onClick={() => {
                            setEditing(comment.id);
                            setDraft(comment.body);
                          }}
                        >
                          Edit
                        </Button>
                        <ConfirmButton
                          label="Delete"
                          message="Delete this comment?"
                          pending={busy === `remove-${comment.id}`}
                          onConfirm={() => void remove(comment.id)}
                        />
                      </>
                    )}
                  </span>
                ) : null}
              </div>
              {editing === comment.id ? (
                <textarea
                  className="chat-input"
                  aria-label="Edit comment"
                  value={draft}
                  maxLength={COMMENT_MAX_CHARS}
                  onChange={(event) => setDraft(event.target.value)}
                />
              ) : (
                <p className="message-body">{comment.body}</p>
              )}
            </div>
          ))}
        </div>
      )}
      {entry?.state === "ready" && entry.data.comments.length > 0 ? (
        <Muted>{entry.data.comments.length} comments</Muted>
      ) : null}
    </Panel>
  );
}

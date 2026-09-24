// Detail-view parts only the lazily loaded views use (the binary and function
// headers, the Functions list and the detail routes), kept out of
// components.tsx so they stay out of the entry chunk.

import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import { EmptyState, Panel, useViewTitle } from "./components";

/**
 * A detail route whose row does not exist (or is outside the caller's scope):
 * a Retry could never succeed, so the page says so, names itself not found and
 * links back to the list.
 */
export function MissingNote({
  what,
  listHref,
  listLabel,
}: {
  /** The row's kind as a title word: "Binary", "Function", "Conversation". */
  what: string;
  listHref: string;
  listLabel: string;
}): ReactNode {
  const title = `${what} not found`;
  useViewTitle(title);
  return (
    <Panel title={title}>
      <EmptyState
        action={
          <a className="btn btn-primary" href={listHref}>
            Back to {listLabel}
          </a>
        }
      >
        No {what.toLowerCase()} has this id. It may have been deleted, or the link is mistyped.
      </EmptyState>
    </Panel>
  );
}

/**
 * The inline rename field: it takes the focus with its text selected, Enter or
 * leaving the field saves, Escape cancels.
 */
export function NameEditor({
  label,
  initial,
  busy,
  onSave,
  onCancel,
}: {
  label: string;
  initial: string;
  busy: boolean;
  onSave: (name: string) => void;
  onCancel: () => void;
}): ReactNode {
  const [draft, setDraft] = useState(initial);
  const inputRef = useRef<HTMLInputElement>(null);
  // Enter and Escape already settled the edit; the blur that follows must not
  // save a second time.
  const skipBlur = useRef(false);
  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);
  return (
    <input
      ref={inputRef}
      aria-label={label}
      value={draft}
      disabled={busy}
      onChange={(event) => setDraft(event.target.value)}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          skipBlur.current = true;
          onSave(draft);
        }
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          skipBlur.current = true;
          onCancel();
        }
      }}
      onBlur={() => {
        if (skipBlur.current) {
          skipBlur.current = false;
          return;
        }
        onSave(draft);
      }}
    />
  );
}

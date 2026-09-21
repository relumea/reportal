// The global search modal (`⌘K` / `Ctrl+K`).  App mounts it and owns the open
// flag; the modal owns the query, the debounced fetch, the roving highlight
// and the focus contract.
//
// Keyboard contract: Escape closes and returns focus to whatever had it, the
// arrow keys move the highlight through the combined result list, Enter opens
// the highlighted hit, and Tab / Shift+Tab cycle the query type.  Tab is what
// the hosted portal uses for the query type, and intercepting it is also what
// keeps focus inside the dialog: nothing else in the modal is tabbable.

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";

import { api } from "../api";
import { ErrorNote, Loading, useDialogShellGuard } from "../components";
import { SEARCH_DEBOUNCE_MS, SEARCH_KIND_LABELS, SEARCH_KINDS } from "../constants";
import type { SearchKind, SearchResults } from "../types";
import { SearchHitRow, hitHref, searchHits } from "./SearchResults";

function cycleKind(current: SearchKind, step: number): SearchKind {
  const index = SEARCH_KINDS.indexOf(current);
  const next = (index + step + SEARCH_KINDS.length) % SEARCH_KINDS.length;
  return SEARCH_KINDS[next];
}

export function SearchModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}): ReactNode {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<SearchKind>("all");
  const [results, setResults] = useState<SearchResults | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [active, setActive] = useState(0);

  // Declared first so its cleanup drops `inert` before the reset effect
  // below returns focus to the shell; restoring into an inert tree fails.
  useDialogShellGuard(open);

  useEffect(() => {
    if (!open) return undefined;
    restoreRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setQuery("");
    setKind("all");
    setResults(null);
    setError(null);
    setLoading(false);
    setActive(0);
    inputRef.current?.focus();
    return () => {
      restoreRef.current?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const trimmed = query.trim();
    if (trimmed === "") {
      setResults(null);
      setError(null);
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    const handle = window.setTimeout(() => {
      api<SearchResults>(`/search?q=${encodeURIComponent(trimmed)}&kind=${kind}`).then(
        (data) => {
          if (cancelled) return;
          setResults(data);
          setError(null);
          setLoading(false);
          setActive(0);
        },
        (failure: unknown) => {
          if (cancelled) return;
          setError(failure);
          setResults(null);
          setLoading(false);
          setActive(0);
        },
      );
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(handle);
    };
  }, [open, query, kind]);

  useEffect(() => {
    if (!open) return undefined;
    const onFocusIn = (event: FocusEvent): void => {
      if (event.target instanceof Node && !dialogRef.current?.contains(event.target)) {
        inputRef.current?.focus();
      }
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, [open]);

  if (!open) return null;

  const hits = results ? searchHits(results) : [];
  const total = results
    ? results.counts.binaries.total +
      results.counts.collections.total +
      results.counts.tags.total +
      results.counts.functions.total
    : 0;

  const openHit = (index: number): void => {
    const hit = hits[index];
    if (!hit) return;
    navigate(hitHref(hit));
    onClose();
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>): void => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    } else if (event.key === "Tab") {
      event.preventDefault();
      setKind((current) => cycleKind(current, event.shiftKey ? -1 : 1));
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((current) => (hits.length ? (current + 1) % hits.length : 0));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((current) => (hits.length ? (current - 1 + hits.length) % hits.length : 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      openHit(active);
    }
  };

  return (
    <div
      className="search-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="search-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Global search"
        ref={dialogRef}
        onKeyDown={onKeyDown}
      >
        <div className="search-dialog-head">
          <input
            ref={inputRef}
            className="search-input"
            type="search"
            role="combobox"
            placeholder="Search binaries, collections, tags and functions"
            aria-label="Search query"
            aria-autocomplete="list"
            aria-expanded={hits.length > 0}
            aria-controls={hits.length ? "search-results" : undefined}
            aria-activedescendant={hits.length ? `search-hit-${active}` : undefined}
            value={query}
            onChange={(event) => {
              const next = event.target.value;
              setQuery(next);
              if (/^[0-9a-fA-F]{64}$/.test(next.trim())) setKind("sha256");
            }}
          />
          <div className="search-kinds" role="tablist" aria-label="Query type">
            {SEARCH_KINDS.map((option) => (
              <button
                key={option}
                type="button"
                role="tab"
                aria-selected={kind === option}
                tabIndex={-1}
                className={kind === option ? "search-kind active" : "search-kind"}
                onClick={() => {
                  setKind(option);
                  inputRef.current?.focus();
                }}
              >
                {SEARCH_KIND_LABELS[option]}
              </button>
            ))}
          </div>
        </div>
        <div className="search-dialog-body" data-search-state={error ? "error" : loading ? "loading" : "done"}>
          {error ? (
            <ErrorNote error={error} />
          ) : hits.length ? (
            <ul id="search-results" className="search-list" role="listbox" aria-label="Search results">
              {hits.map((hit, index) => (
                <SearchHitRow
                  key={`${hit.kind}-${index}`}
                  id={`search-hit-${index}`}
                  hit={hit}
                  active={index === active}
                  onSelect={onClose}
                />
              ))}
            </ul>
          ) : query.trim() === "" ? (
            <p className="muted">
              Type a name, a hash prefix, a collection, a tag or a function. Tab changes the query type.
            </p>
          ) : loading ? (
            <Loading label="Searching" />
          ) : (
            <p className="muted">
              No results for &quot;{query.trim()}&quot; as {SEARCH_KIND_LABELS[kind]}.
            </p>
          )}
          {results && hits.length ? (
            <p className="muted search-count">
              {hits.length} of {total} matches shown
            </p>
          ) : null}
        </div>
        <div className="search-dialog-foot muted">
          ↑ ↓ move · Enter opens · Tab changes the query type · Esc closes
        </div>
      </div>
    </div>
  );
}

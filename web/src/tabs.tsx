import { useId, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { flushSync } from "react-dom";
import { useSearchParams } from "react-router";

import "./tabs.css";

// Arrow keys move between tabs (the WAI-ARIA tabs pattern), wrapping round.
const ARROW_STEPS: Partial<Record<string, number>> = { ArrowRight: 1, ArrowLeft: -1 };

export interface TabSpec {
  id: string;
  label: string;
  content: ReactNode;
}

/**
 * A detail page's regions as tabs, the active one named in the route query
 * under *param* so a reload or a shared link opens the same tab.
 *
 * Every tab stays mounted and the inactive ones are `hidden`: their panels
 * keep their state, and `focusPanel` (keys.ts) finds a panel in any tab and
 * clicks that tab open, which switches synchronously (`flushSync`) so the
 * caller can scroll to it in the same event.  The router wraps its own state
 * updates in a transition, so the active tab is local state the URL mirrors.
 */
export function Tabs({
  tabs,
  label,
  param,
  fallback,
}: {
  tabs: TabSpec[];
  /** The tablist's accessible name. */
  label: string;
  param: string;
  /** The tab shown when the query names none (or an unknown one). */
  fallback: string;
}): ReactNode {
  const base = useId();
  const [params, setParams] = useSearchParams();
  const requested = params.get(param);
  const fromUrl =
    requested !== null && tabs.some((tab) => tab.id === requested) ? requested : fallback;
  const [active, setActive] = useState(fromUrl);
  // Back/forward (or a link) changing the query moves the tab with it.
  const [shown, setShown] = useState(fromUrl);
  if (shown !== fromUrl) {
    setShown(fromUrl);
    setActive(fromUrl);
  }

  const select = (id: string): void => {
    flushSync(() => setActive(id));
    setParams(
      (next) => {
        next.set(param, id);
        return next;
      },
      { replace: true },
    );
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    const step = ARROW_STEPS[event.key];
    if (step === undefined) return;
    event.preventDefault();
    const index = tabs.findIndex((tab) => tab.id === active);
    const next = tabs[(index + step + tabs.length) % tabs.length];
    select(next.id);
    document.getElementById(`${base}-tab-${next.id}`)?.focus();
  };

  return (
    <>
      <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            id={`${base}-tab-${tab.id}`}
            type="button"
            role="tab"
            className="tab"
            aria-selected={tab.id === active}
            aria-controls={`${base}-panel-${tab.id}`}
            tabIndex={tab.id === active ? 0 : -1}
            onClick={() => select(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          id={`${base}-panel-${tab.id}`}
          role="tabpanel"
          className="tab-panel"
          aria-labelledby={`${base}-tab-${tab.id}`}
          hidden={tab.id !== active}
        >
          {tab.content}
        </div>
      ))}
    </>
  );
}

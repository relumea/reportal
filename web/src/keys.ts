// The SPA's keyboard layer: one registry every shortcut lives in, installed
// once by the shell.  The cheatsheet renders this registry, so the documented
// set and the live set cannot drift.
//
// A binding is `(combo, scope, description, handler)`.  A combo is either a
// chord (`mod+k`: `mod` is Command on a Mac and Control elsewhere, so one
// binding covers both) or a space-separated sequence (`g d`: the `g` prefix
// stays armed for `PREFIX_TIMEOUT_MS`).
//
// Precedence: a `view`-scoped binding is matched before a `global` one with
// the same combo, so a view can override the shell, and within a scope the
// first registration wins.  Registering a combo twice in one scope throws:
// two handlers for one chord is a defect, not a configuration.
//
// Two hard rules:
//
// * A binding never fires while the focus owns text (an input, a textarea, a
//   select or a contenteditable), which is what keeps a literal `k` in a
//   filter box from opening the search dialog
//   (`web/tests/search-modal.spec.ts` pins that).  `whenTyping` is the
//   exception: `mod+enter` and Escape have to reach an edited type field.
// * A binding never fires while a modal dialog owns the keyboard, so the keys
//   that opened the cheatsheet cannot act behind it.
//
// A matched binding consumes the key (`preventDefault`), whether or not its
// handler could act on the current view: a shortcut that sometimes falls
// through to the browser would make the same key mean two things.

/** True when a focused element owns keyboard text, so a shortcut must not fire. */
function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  return ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

/** Where a binding is live: the whole shell, or the view that registered it. */
export type ShortcutScope = "global" | "view";

export interface Shortcut {
  /** Canonical combo: `mod+k` for a chord, `g d` for a prefix sequence. */
  combo: string;
  scope: ShortcutScope;
  /** What the shortcut does, as the cheatsheet renders it. */
  description: string;
  /** False means the binding did not act; typing targets keep their own key. */
  handler: (event: KeyboardEvent) => boolean | void | Promise<void>;
  /** Fire while an input owns the keyboard.  `mod+enter` / Escape on a type field. */
  whenTyping?: boolean;
}

/** How long a prefix stays armed after its first key. */
const PREFIX_TIMEOUT_MS = 1500;

/** Modifiers a combo may name, in the order a canonical chord lists them. */
const MODIFIER_ORDER = ["mod", "alt", "shift"] as const;

/** Aliases folded onto the canonical modifier names. */
const MODIFIER_ALIASES: Record<string, string> = {
  mod: "mod",
  cmd: "mod",
  meta: "mod",
  ctrl: "mod",
  control: "mod",
  alt: "alt",
  option: "alt",
  shift: "shift",
};

// Keys whose shift state belongs to the combo.  A shifted punctuation key
// (`?` is Shift+`/`) is the same binding as the character it produces.
const SHIFTED_KEY = /^[a-z0-9]$/;

const registry: Shortcut[] = [];
let pending: string | null = null;
let pendingTimer: number | null = null;

function canonicalChord(chord: string): string {
  const parts = chord.split("+").map((part) => part.trim().toLowerCase()).filter(Boolean);
  const key = parts.pop() ?? "";
  const named = key === " " || key === "space" ? "space" : key;
  const modifiers = MODIFIER_ORDER.filter((name) =>
    parts.some((part) => MODIFIER_ALIASES[part] === name),
  );
  return [...modifiers, named].join("+");
}

/** The canonical spelling of *combo*, which is what the registry stores. */
export function normalizeCombo(combo: string): string {
  return combo
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(canonicalChord)
    .join(" ");
}

/** The combo an event carries, or null for a bare modifier. */
function comboOf(event: KeyboardEvent): string | null {
  const raw = event.key.toLowerCase();
  if (raw === "shift" || raw === "control" || raw === "meta" || raw === "alt") return null;
  const key = raw === " " ? "space" : raw;
  const modifiers: string[] = [];
  if (event.metaKey || event.ctrlKey) modifiers.push("mod");
  if (event.altKey) modifiers.push("alt");
  if (event.shiftKey && SHIFTED_KEY.test(key)) modifiers.push("shift");
  return [...modifiers, key].join("+");
}

/**
 * Register one binding; returns the function that unregisters it.
 *
 * Throws when the combo is already registered in the same scope, so a
 * conflicting binding fails at registration rather than silently winning or
 * losing at dispatch time.
 */
export function registerShortcut(shortcut: Shortcut): () => void {
  const combo = normalizeCombo(shortcut.combo);
  if (!combo) throw new Error(`empty shortcut combo: ${shortcut.combo}`);
  if (registry.some((entry) => entry.combo === combo && entry.scope === shortcut.scope)) {
    throw new Error(`shortcut ${combo} is already registered in scope ${shortcut.scope}`);
  }
  const entry: Shortcut = { ...shortcut, combo };
  registry.push(entry);
  return () => {
    const index = registry.indexOf(entry);
    if (index >= 0) registry.splice(index, 1);
  };
}

/** The registered bindings, in registration order. */
export function shortcuts(): Shortcut[] {
  return [...registry];
}

/** The binding a combo resolves to: the view-scoped one first, then the shell's. */
export function resolveShortcut(combo: string): Shortcut | undefined {
  return (
    registry.find((entry) => entry.scope === "view" && entry.combo === combo) ??
    registry.find((entry) => entry.scope === "global" && entry.combo === combo)
  );
}

/** True when *combo* starts a registered sequence (`g` for `g d`). */
export function isPrefix(combo: string): boolean {
  return registry.some((entry) => entry.combo.startsWith(`${combo} `));
}

function clearPending(): void {
  pending = null;
  if (pendingTimer !== null) {
    window.clearTimeout(pendingTimer);
    pendingTimer = null;
  }
}

function armPending(combo: string): void {
  clearPending();
  pending = combo;
  pendingTimer = window.setTimeout(clearPending, PREFIX_TIMEOUT_MS);
}

/** True when a modal dialog owns the keyboard, so no shortcut may act. */
function inModal(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest('[aria-modal="true"]') !== null;
}

function onKeyDown(event: KeyboardEvent): void {
  if (event.defaultPrevented) return;
  if (inModal(event.target)) return;
  const typing = isTypingTarget(event.target);
  const chord = comboOf(event);
  if (chord === null) return;
  const sequence = pending === null ? chord : `${pending} ${chord}`;
  clearPending();
  const binding = resolveShortcut(sequence) ?? resolveShortcut(chord);
  if (binding === undefined) {
    if (!typing && isPrefix(chord)) armPending(chord);
    return;
  }
  if (typing && !binding.whenTyping) return;
  const acted = binding.handler(event);
  // A typing-target binding that did not act (Escape on a filter box) must
  // leave the field's own key, so a search input can still clear.
  if (typing && acted === false) return;
  event.preventDefault();
}

/**
 * Install the key listener; returns the function that removes it.
 *
 * The listener sits on `window`, which is where a key event that started on
 * the focused element ends up after bubbling (and where a synthetic event a
 * test dispatches without a focus target arrives); a listener on `document`
 * would miss the latter, since an event dispatched on `window` does not travel
 * down to it.
 */
export function installShortcuts(): () => void {
  window.addEventListener("keydown", onKeyDown);
  return () => {
    window.removeEventListener("keydown", onKeyDown);
    clearPending();
  };
}

/** True on a Mac, where `mod` renders as Command. */
export function isMac(): boolean {
  return /mac|iphone|ipad/i.test(navigator.userAgent);
}

function displayToken(token: string, mac: boolean): string {
  if (token === "mod") return mac ? "⌘" : "Ctrl";
  if (token === "alt") return mac ? "⌥" : "Alt";
  if (token === "shift") return mac ? "⇧" : "Shift";
  if (token === "escape") return "Esc";
  if (token === "space") return "Space";
  return token.length === 1 ? token.toUpperCase() : token;
}

/** How a combo reads in the cheatsheet: `⌘K`, `Ctrl+K`, `G then D`, `?`. */
export function displayCombo(combo: string, mac: boolean): string {
  return combo
    .split(" ")
    .map((chord) =>
      chord
        .split("+")
        .map((token) => displayToken(token, mac))
        .join(mac ? "" : "+"),
    )
    .join(" then ");
}

/**
 * Focus the current view's filter box: the first `input[type="search"]` in the
 * content area, which is the convention every filter field follows.
 */
export function focusViewFilter(): boolean {
  const field = document.querySelector<HTMLInputElement>('#content input[type="search"]');
  if (field === null) return false;
  field.focus();
  return true;
}

/**
 * Focus the current view's first filter control (the first select or input in
 * the content toolbar).  `/` still owns the search box; `P` is the rest of
 * the filter row.
 */
export function focusViewFilters(): boolean {
  const control = document.querySelector<HTMLElement>(
    "#content .toolbar select, #content .toolbar input",
  );
  if (control === null) return false;
  control.focus();
  return true;
}

/**
 * Scroll to the *delta*th panel in the content area, relative to the first one
 * whose top is at or below the viewport: `]` steps to the next section, `[`
 * to the previous, which is the hosted portal's section cycling.  Returns false
 * on a view that has no panels to cycle.
 */
export function cycleViewSection(delta: number): boolean {
  const panels = Array.from(document.querySelectorAll<HTMLElement>('#content section.panel'));
  if (panels.length === 0) return false;
  const tops = panels.map((panel) => panel.getBoundingClientRect().top);
  // The section in view is the last one whose top has passed the header, so a
  // step from a scrolled page moves to the next one rather than jumping back.
  const current = tops.reduce((found, top, index) => (top <= 96 ? index : found), 0);
  const next = Math.min(panels.length - 1, Math.max(0, current + delta));
  panels[next].scrollIntoView({ behavior: "smooth", block: "start" });
  panels[next].focus({ preventScroll: true });
  return true;
}

/**
 * Jump to the named panel in the content area.  Hosted O/T/S/A/M bind this;
 * a title that is not on the page leaves the key inert.
 */
export function focusPanel(title: string): boolean {
  const needle = title.toLowerCase();
  const panel = Array.from(
    document.querySelectorAll<HTMLElement>("#content section.panel"),
  ).find((entry) => {
    const heading = entry.querySelector(".panel-title")?.textContent?.trim().toLowerCase() ?? "";
    return heading === needle || heading.startsWith(needle);
  });
  if (panel === undefined) return false;
  const heading = panel.querySelector<HTMLElement>(".panel-title") ?? panel;
  heading.scrollIntoView({ behavior: "instant", block: "start" });
  panel.focus({ preventScroll: true });
  return true;
}

/**
 * Jump to Memory and focus its address box.  Hosted `G` is this; bare `g`
 * stays the nav prefix, so the shell binds `shift+g`.
 */
export function focusMemoryGoto(): boolean {
  if (!focusPanel("Memory")) return false;
  const panel = Array.from(
    document.querySelectorAll<HTMLElement>("#content section.panel"),
  ).find((entry) => {
    const heading = entry.querySelector(".panel-title")?.textContent?.trim().toLowerCase() ?? "";
    return heading === "memory" || heading.startsWith("memory");
  });
  const field = panel?.querySelector<HTMLInputElement>('input[type="text"]');
  if (field === undefined || field === null) return false;
  field.focus();
  return true;
}

/**
 * Move the focus *delta* rows through the first focusable table in the content
 * area (a row `DataTable` makes tabbable because clicking it navigates).  A
 * table with no such row leaves the keys inert, and the focus clamps at the
 * ends rather than wrapping.
 */
function tableRows(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('#content table.data-table tbody tr[tabindex="0"]'),
  );
}

export function moveTableRow(delta: number): boolean {
  const rows = tableRows();
  if (rows.length === 0) return false;
  const current = rows.indexOf(document.activeElement as HTMLElement);
  const next =
    current === -1
      ? delta > 0
        ? 0
        : rows.length - 1
      : Math.min(rows.length - 1, Math.max(0, current + delta));
  rows[next].focus();
  return true;
}

/**
 * Jump to the first or last tabbable row of the view's first data table.
 * Shift+J / Shift+K on a list with no such row stay inert.
 */
export function jumpTableRow(end: boolean): boolean {
  const rows = tableRows();
  if (rows.length === 0) return false;
  rows[end ? rows.length - 1 : 0].focus();
  return true;
}

/**
 * Click the named action of the focused table row.  The Functions Rename
 * button is the one this exists for; a view without that button leaves `R`
 * inert.
 */
export function clickFocusedRowAction(label: string): boolean {
  const row = document.activeElement;
  if (!(row instanceof HTMLElement) || row.tagName !== "TR") return false;
  const button = Array.from(row.querySelectorAll("button")).find(
    (entry) => entry.textContent?.trim() === label,
  );
  if (button === undefined) return false;
  button.click();
  return true;
}

const SAVE_LABELS = new Set(["Save", "Save fields"]);

/**
 * Click Save on the focused type field.  Looks in the nearest actions cell,
 * then the toolbar, then the card, so a member Save wins over Save fields.
 */
export function clickFocusedSave(): boolean {
  const target = document.activeElement;
  if (!(target instanceof HTMLElement)) return false;
  const scopes = [
    target.closest(".actions-cell"),
    target.closest(".toolbar"),
    target.closest(".card"),
  ];
  for (const scope of scopes) {
    if (scope === null) continue;
    const button = Array.from(scope.querySelectorAll("button")).find((entry) =>
      SAVE_LABELS.has(entry.textContent?.trim() ?? ""),
    );
    if (button !== undefined) {
      button.click();
      return true;
    }
  }
  return false;
}

let typeEditRestore: (() => boolean) | null = null;

/** Publish the focused type field's restore; DataTypesPanel is the only writer,
 * and it publishes null on blur and again when the panel unmounts. */
export function setTypeEditRestore(handler: (() => boolean) | null): void {
  typeEditRestore = handler;
}

/**
 * Restore the focused type field.  Hosted Esc discards an in-progress type
 * edit; a field that has not published a restore is left inert.
 */
export function discardFocusedTypeEdit(): boolean {
  return typeEditRestore?.() ?? false;
}

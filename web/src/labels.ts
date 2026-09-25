// Display wording the lazy views share: counts in the right number, stored
// sizes, portal vocabulary in sentence case and the sort and scope labels.
// Kept apart from constants.ts and components.tsx, which the shell imports, so
// view-only text never lands in the entry chunk (its budget: tools/smoke_spa.py).

import { NA } from "./components";
import type { BinaryOrder, CollectionOrder, WorkspaceFilter } from "./constants";

/** `count` with the noun in the matching number: "1 binary", "2 binaries". */
export function countOf(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

/** A stored byte size; 0 means none was recorded, since uploads refuse an empty file. */
export function byteSize(bytes: number): string {
  return bytes > 0 ? bytes.toLocaleString() : NA;
}

/**
 * A portal vocabulary value ("Strong Match", "No Debug Info", "AI Agent") as the
 * SPA prints it: sentence case, an all-capitals word such as `AI` kept.  The
 * value itself stays the API's, for filters and comparisons.
 */
export function sentenceLabel(value: string): string {
  return value
    .split(" ")
    .map((word, index) => (index === 0 || word === word.toUpperCase() ? word : word.toLowerCase()))
    .join(" ");
}

export const BINARY_ORDER_LABELS: Record<BinaryOrder, string> = {
  id: "Oldest first",
  newest: "Newest first",
  name: "Name (A to Z)",
  "name-desc": "Name (Z to A)",
  size: "Size (small first)",
  "size-desc": "Size (large first)",
};

export const COLLECTION_ORDER_LABELS: Record<CollectionOrder, string> = {
  id: "Oldest first",
  name: "Name (A to Z)",
  size: "Most binaries first",
  updated: "Recently updated",
  owner: "Owning team",
};

export const WORKSPACE_FILTER_LABELS: Record<WorkspaceFilter, string> = {
  personal: "Personal",
  team: "Team",
  public: "Public",
};

// The search result model shared by the Search view and the global search
// modal.  A hit is one typed row plus the kind that produced it; `hitHref`
// and `hitTitle` are the one place a hit becomes a destination and a name.
//
// The two surfaces render differently on purpose: the Search view groups rows
// into one table per kind (its established, tested contract) while the modal
// is a single list walked with the arrow keys.  Both read the same `SearchHit`
// values, so the navigation and identification logic is not duplicated.

import type { ReactNode } from "react";
import { Link } from "react-router";

import { hex } from "../components";
import type {
  SearchBinaryRow,
  SearchCollectionRow,
  SearchFunctionRow,
  SearchResults,
  SearchTagRow,
} from "../types";

/** Compact hash text without a nested Copy control (options must stay inert). */
function compactHash(value: string): ReactNode {
  const shown = value.length > 12 ? `${value.slice(0, 12)}…` : value;
  return (
    <span className="mono" title={value}>
      {shown}
    </span>
  );
}

/** One search result, tagged with the group it came from. */
export type SearchHit =
  | { kind: "binary"; row: SearchBinaryRow }
  | { kind: "collection"; row: SearchCollectionRow }
  | { kind: "tag"; row: SearchTagRow }
  | { kind: "function"; row: SearchFunctionRow };

export function binaryHref(id: number): string {
  return `/binaries/${id}`;
}

export function functionHref(id: number): string {
  return `/functions/${id}`;
}

// reportal has no per-collection or per-tag detail route, so those hits open
// the owning view with `?id=` so the matched row is selected.
export function collectionHref(id: number): string {
  return `/collections?id=${id}`;
}

export function tagHref(id: number): string {
  return `/tags?id=${id}`;
}

export function searchHits(results: SearchResults): SearchHit[] {
  return [
    ...results.binaries.map((row): SearchHit => ({ kind: "binary", row })),
    ...results.collections.map((row): SearchHit => ({ kind: "collection", row })),
    ...results.tags.map((row): SearchHit => ({ kind: "tag", row })),
    ...results.functions.map((row): SearchHit => ({ kind: "function", row })),
  ];
}

export function hitHref(hit: SearchHit): string {
  if (hit.kind === "binary") return binaryHref(hit.row.id);
  if (hit.kind === "function") return functionHref(hit.row.id);
  if (hit.kind === "collection") return collectionHref(hit.row.id);
  return tagHref(hit.row.id);
}

/** The kind label a result row shows. */
function hitKindLabel(hit: SearchHit): string {
  return hit.kind === "binary" ? "binary" : hit.kind;
}

function _tags(tags: string[]): ReactNode {
  if (!tags.length) return null;
  return <span className="search-row-tags">{tags.slice(0, 3).join(", ")}</span>;
}

/** One result row's metadata line: the fields the store holds, per kind. */
function hitMeta(hit: SearchHit): ReactNode {
  if (hit.kind === "binary") {
    return (
      <>
        <span className="search-row-kind">{hitKindLabel(hit)}</span>
        {compactHash(hit.row.sha256)}
        <span>{hit.row.size.toLocaleString()} B</span>
        <span>{[hit.row.format, hit.row.arch].filter(Boolean).join(" / ") || "n/a"}</span>
        {_tags(hit.row.tags)}
        <span className="muted">{hit.row.created_at}</span>
        <span className="muted">matched {hit.row.match}</span>
      </>
    );
  }
  if (hit.kind === "collection") {
    return (
      <>
        <span className="search-row-kind">{hitKindLabel(hit)}</span>
        <span>{hit.row.binary_count} binaries</span>
        <span className="muted">{hit.row.visibility || "public"}</span>
        {_tags([hit.row.description].filter(Boolean))}
        <span className="muted">{hit.row.created_at}</span>
        <span className="muted">matched {hit.row.match}</span>
      </>
    );
  }
  if (hit.kind === "tag") {
    return (
      <>
        <span className="search-row-kind">{hitKindLabel(hit)}</span>
        <span>{hit.row.binary_count} binaries</span>
      </>
    );
  }
  return (
    <>
      <span className="search-row-kind">function</span>
      <span className="mono">{hex(hit.row.va)}</span>
      <span>{hit.row.status}</span>
      <span>{hit.row.name}</span>
    </>
  );
}

/** The full label a row's navigation link carries. */
function hitTitle(hit: SearchHit): string {
  if (hit.kind === "function") return `${hit.row.name} @ ${hex(hit.row.va)}`;
  if (hit.kind === "binary") return hit.row.name;
  if (hit.kind === "collection") return hit.row.name;
  return hit.row.name;
}

/**
 * One hit as a focusable list row.  `active` is the roving highlight the modal
 * moves with the arrow keys; a row is a link so a mouse click and Enter share
 * the same destination, and `onSelect` lets the modal close on a click the way
 * it does on Enter.
 */
export function SearchHitRow({
  hit,
  active,
  onSelect,
  id,
}: {
  hit: SearchHit;
  active: boolean;
  onSelect?: () => void;
  id?: string;
}): ReactNode {
  return (
    <li
      id={id}
      role="option"
      aria-selected={active}
      className={active ? "search-row active" : "search-row"}
      data-hit-kind={hit.kind}
    >
      <Link to={hitHref(hit)} onClick={onSelect} tabIndex={-1}>
        <span className="search-row-label">{hitTitle(hit)}</span>
        <span className="search-row-meta">{hitMeta(hit)}</span>
      </Link>
    </li>
  );
}

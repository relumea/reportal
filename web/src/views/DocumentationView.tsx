// The Documentation view: the portal's own manual, rendered in the portal.
//
// The server reads `docs/*.md` and `CHANGELOG.md` and answers a page as
// *blocks* rather than markup (`GET /api/docs`, `GET /api/docs/<slug>`), so
// nothing is ever injected as HTML and the SPA carries no markdown library.
// This view is the renderer: an inline pass for links, code spans and
// emphasis, and one element per block kind.  The index is the same view with
// no slug, which is what `/docs` shows.

import { Fragment, useEffect, useState } from "react";
import type { ReactNode } from "react";

import { Link, useParams } from "react-router";

import { api } from "../api";
import { Button, ErrorNote, Loading, Muted, Panel } from "../components";
import type { DocBlock, DocIndex, DocListItem, DocPage, DocPageBody } from "../types";
import { useAsync } from "../useAsync";

/** The changelog is a page like any other, so its slug is the changelog route. */
const CHANGELOG_SLUG = "changelog";

/** Inline markdown, in one pass: code spans, links, bold, then italics.  The
 * order is what keeps `**bold**` from being read as two italics. */
const INLINE = /(`[^`]+`)|(\[[^\]]+\]\([^)\s]+\))|(\*\*[^*]+\*\*)|(\*[^*]+\*)/g;

/** A documentation link's target, or null for anything else. */
function linkTarget(target: string): { url: string; internal: boolean } | null {
  if (/^https?:\/\//.test(target)) return { url: target, internal: false };
  if (target.startsWith("/docs/")) return { url: target, internal: true };
  return null;
}

/** Render one run of text with its inline markdown as React nodes. */
export function renderInline(text: string): ReactNode {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let key = 0;
  for (const match of text.matchAll(INLINE)) {
    const start = match.index ?? 0;
    if (start > cursor) nodes.push(text.slice(cursor, start));
    const token = match[0];
    if (token.startsWith("`")) {
      nodes.push(<code key={key++}>{token.slice(1, -1)}</code>);
    } else if (token.startsWith("[")) {
      const split = token.indexOf("](");
      const label = token.slice(1, split);
      const target = token.slice(split + 2, -1);
      const link = linkTarget(target);
      if (link === null) nodes.push(label);
      else if (link.internal) {
        nodes.push(
          <Link key={key++} to={link.url}>
            {label}
          </Link>,
        );
      } else {
        nodes.push(
          <a key={key++} href={link.url} target="_blank" rel="noreferrer noopener">
            {label}
          </a>,
        );
      }
    } else if (token.startsWith("**")) {
      nodes.push(<strong key={key++}>{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(<em key={key++}>{token.slice(1, -1)}</em>);
    }
    cursor = start + token.length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return <>{nodes.map((node, index) => <Fragment key={index}>{node}</Fragment>)}</>;
}

/** One list: nested by each item's depth, ordered or not.  The bullets carry
 * the nesting rather than a tree of `<ul>`s, since the server sends a flat
 * block and the depth is the only structure it has. */
function DocList({ ordered, items }: { ordered: boolean; items: DocListItem[] }): ReactNode {
  return (
    <div className="doc-list" data-ordered={ordered}>
      {items.map((item, index) => (
        <p key={index} style={{ paddingLeft: `${Math.min(item.depth ?? 0, 4) * 1.1}rem` }}>
          <span className="doc-bullet" aria-hidden="true">
            {ordered ? `${index + 1}.` : "\u2022"}
          </span>
          <span className="doc-item-text">{renderInline(item.text)}</span>
        </p>
      ))}
    </div>
  );
}

function DocTable({ header, rows }: { header: string[]; rows: string[][] }): ReactNode {
  return (
    <div className="doc-table-wrap">
      <table className="doc-table">
        {header.length ? (
          <thead>
            <tr>
              {header.map((cell, index) => (
                <th key={index}>{renderInline(cell)}</th>
              ))}
            </tr>
          </thead>
        ) : null}
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{renderInline(cell)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** One parsed block.  An unknown kind falls back to its text, so a construct
 * the server learns later is shown rather than dropped. */
export function DocBlockView({ block }: { block: DocBlock }): ReactNode {
  switch (block.kind) {
    case "heading":
      return (
        <h3 className="doc-heading" data-level={block.level ?? 2}>
          {renderInline(block.text ?? "")}
        </h3>
      );
    case "code":
      return (
        <pre className="doc-code" data-lang={block.lang || undefined}>
          <code>{block.text ?? ""}</code>
        </pre>
      );
    case "list":
      return <DocList ordered={Boolean(block.ordered)} items={block.items ?? []} />;
    case "table":
      return <DocTable header={block.header ?? []} rows={block.rows ?? []} />;
    case "quote":
      return <blockquote className="doc-quote">{renderInline(block.text ?? "")}</blockquote>;
    default:
      return <p className="doc-paragraph">{renderInline(block.text ?? "")}</p>;
  }
}

/** The page index: every shipped document, in reading order. */
export function DocsIndex(): ReactNode {
  const { data, error, reload } = useAsync(() => api<DocIndex>("/docs"), []);

  if (error) return <ErrorNote error={error} onRetry={reload} />;
  if (!data) {
    return (
      <Panel title="Documentation">
        <Loading label="Listing the shipped pages" rows={3} />
      </Panel>
    );
  }
  return (
    <Panel
      title="Documentation"
      subtitle={`${data.count} page(s), served from the workspace rather than a checkout.`}
      actions={
        <Button tone="ghost" onClick={() => reload()}>
          Refresh
        </Button>
      }
    >
      <Muted>
        These are the repository's own documents, parsed server-side into headings, paragraphs,
        lists, code, quotes and tables. Set REPORTAL_DOCS to read a different directory, which is
        what makes this page useful once the portal runs somewhere the checkout is not.
      </Muted>
      <div className="doc-index">
        {data.pages.map((page) => (
          <Link key={page.slug} className="doc-card" to={`/docs/${page.slug}`}>
            <span className="doc-card-slug">{page.slug}</span>
            <span className="doc-card-title">{page.title}</span>
          </Link>
        ))}
      </div>
    </Panel>
  );
}

/** One page: the on-this-page list beside the rendered blocks. */
function DocPageView({ slug }: { slug: string }): ReactNode {
  const { data, error, reload } = useAsync(() => api<DocPageBody>(`/docs/${slug}`), [slug]);
  const [active, setActive] = useState("");

  // The heading anchors are the ids the reader scrolls to; watching them is
  // what marks the current section, without a second source of truth.
  useEffect(() => {
    if (!data) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) if (entry.isIntersecting) setActive(entry.target.id);
      },
      { rootMargin: "-72px 0px -70% 0px" },
    );
    for (const heading of data.headings) {
      const node = document.getElementById(heading.id);
      if (node) observer.observe(node);
    }
    return () => observer.disconnect();
  }, [data]);

  if (error) return <ErrorNote error={error} onRetry={reload} />;
  if (!data) {
    return (
      <Panel title={slug}>
        <Loading label={`Reading ${slug}`} rows={6} />
      </Panel>
    );
  }
  let heading = 0;
  return (
    <Panel
      title={data.title}
      subtitle={`${data.source} \u00b7 reportal v${data.version}`}
      actions={
        <>
          <Link className="btn" to="/docs">
            All pages
          </Link>
          <Button tone="ghost" onClick={() => reload()}>
            Refresh
          </Button>
        </>
      }
    >
      <div className="doc-layout">
        <nav className="doc-toc" aria-label="On this page">
          <span className="doc-toc-label">On this page</span>
          {data.headings.length ? (
            data.headings.map((entry) => (
              <a
                key={entry.id}
                href={`#${entry.id}`}
                className={active === entry.id ? "doc-toc-link active" : "doc-toc-link"}
                onClick={(event) => {
                  event.preventDefault();
                  document.getElementById(entry.id)?.scrollIntoView({ behavior: "smooth" });
                  setActive(entry.id);
                }}
              >
                {entry.text}
              </a>
            ))
          ) : (
            <Muted>No sub-headings.</Muted>
          )}
        </nav>
        <article className="doc-body">
          {data.blocks.map((block, index) => {
            if (block.kind !== "heading") return <DocBlockView key={index} block={block} />;
            const anchor = data.headings[heading];
            heading += 1;
            return (
              <div key={index} id={anchor?.id}>
                <DocBlockView block={block} />
              </div>
            );
          })}
          <DocPager previous={data.previous} next={data.next} />
        </article>
      </div>
    </Panel>
  );
}

/** The reading-order links at the foot of a page, the hosted manual's pair.
 *  The server sends them, so the index and this control cannot disagree. */
function DocPager({
  previous,
  next,
}: {
  previous: DocPage | null;
  next: DocPage | null;
}): ReactNode {
  if (previous === null && next === null) return null;
  return (
    <nav className="doc-pager" aria-label="Previous and next page">
      {previous === null ? (
        <span />
      ) : (
        <Link className="doc-pager-link" to={`/docs/${previous.slug}`} rel="prev">
          <span className="doc-pager-label">Previous</span>
          {previous.title}
        </Link>
      )}
      {next === null ? (
        <span />
      ) : (
        <Link className="doc-pager-link next" to={`/docs/${next.slug}`} rel="next">
          <span className="doc-pager-label">Next</span>
          {next.title}
        </Link>
      )}
    </nav>
  );
}

export function DocumentationView(): ReactNode {
  const { slug } = useParams();
  const resolved = slug ?? "";
  if (!resolved) return <DocsIndex />;
  return <DocPageView slug={resolved} />;
}

export function ChangelogView(): ReactNode {
  return <DocPageView slug={CHANGELOG_SLUG} />;
}

import type { HLJSApi, Language } from "highlight.js";
import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import { Fragment, useMemo } from "react";
import type { ReactNode } from "react";

import { CopyButton } from "../components";
import "./listing.css";

// Typedefs decompilers emit that the stock C grammar does not know as types.
const DECOMPILER_TYPES = [
  "undefined",
  "undefined1",
  "undefined2",
  "undefined3",
  "undefined4",
  "undefined5",
  "undefined6",
  "undefined7",
  "undefined8",
  "byte",
  "word",
  "dword",
  "qword",
  "BOOL",
  "BYTE",
  "WORD",
  "DWORD",
  "UINT",
  "HANDLE",
  "HWND",
  "LPVOID",
  "LPSTR",
  "LPCSTR",
];

/** highlight.js's C grammar with the decompiler typedefs added to its types. */
function decompiledC(api: HLJSApi): Language {
  const language = c(api);

  // Every nested mode of the grammar references this one keyword table, so the
  // added types apply in every context.
  const { keywords } = language;

  if (!(keywords instanceof Object) || Array.isArray(keywords) || !Array.isArray(keywords.type)) {
    throw new TypeError("highlight.js c grammar: keywords.type is not a word list");
  }

  keywords.type = [...keywords.type, ...DECOMPILER_TYPES];

  return language;
}

hljs.registerLanguage("c", decompiledC);

const NO_LINKS: Readonly<Record<string, number>> = {};

// A word that can be a stored function name; the same pattern the server
// matches names with (lineage._IDENTIFIER), dotted split parts included.
const IDENTIFIER = /\b[A-Za-z_]\w*(?:\.\w+)*/gu;

/** *text* with each name in *links* turned into a link to that function. */
function linkNames(text: string, links: Readonly<Record<string, number>>): ReactNode {
  const parts: ReactNode[] = [];
  let last = 0;

  for (const match of text.matchAll(IDENTIFIER)) {
    const id = Object.hasOwn(links, match[0]) ? links[match[0]] : undefined;

    if (id === undefined) continue;

    parts.push(
      text.slice(last, match.index),
      <a key={match.index} className="c-source-link" href={`#/functions/${id}`}>
        {match[0]}
      </a>,
    );
    last = match.index + match[0].length;
  }

  if (parts.length === 0) return text;

  parts.push(text.slice(last));

  return parts;
}

/** A node of highlight.js's output as React: spans keep their class, linked names become links. */
function toReact(node: ChildNode, key: number, links: Readonly<Record<string, number>>): ReactNode {
  if (node instanceof HTMLSpanElement) {
    return (
      <span key={key} className={node.className}>
        {Array.from(node.childNodes, (child, index) => toReact(child, index, links))}
      </span>
    );
  }

  return <Fragment key={key}>{linkNames(node.textContent ?? "", links)}</Fragment>;
}

/** Decompiled C, coloured by highlight.js; a name in *links* opens that function. */
export function CSource({
  text,
  title,
  links = NO_LINKS,
}: {
  text: string;
  title: string;
  links?: Readonly<Record<string, number>>;
}): ReactNode {
  // highlight.js returns HTML with the source text escaped; parsing it into
  // nodes and rebuilding them as React elements keeps innerHTML out of the page.
  const parts = useMemo(() => {
    const html = hljs.highlight(text, { language: "c", ignoreIllegals: true }).value;
    const { body } = new DOMParser().parseFromString(html, "text/html");

    return Array.from(body.childNodes, (node, index) => toReact(node, index, links));
  }, [text, links]);

  return (
    <div className="listing">
      <div className="code-head">
        <span className="code-title">{title}</span>
        <CopyButton text={text} />
      </div>
      <pre className="code-scroll c-source">{parts}</pre>
    </div>
  );
}

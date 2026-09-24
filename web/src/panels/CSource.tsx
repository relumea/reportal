import type { HLJSApi, Language } from "highlight.js";
import hljs from "highlight.js/lib/core";
import c from "highlight.js/lib/languages/c";
import { useMemo } from "react";
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

/** A node of highlight.js's output as React: its spans keep their class, text stays text. */
function toReact(node: ChildNode, key: number): ReactNode {
  if (node instanceof HTMLSpanElement) {
    return (
      <span key={key} className={node.className}>
        {Array.from(node.childNodes, toReact)}
      </span>
    );
  }

  return node.textContent;
}

/** Decompiled C, coloured by highlight.js. */
export function CSource({ text, title }: { text: string; title: string }): ReactNode {
  // highlight.js returns HTML with the source text escaped; parsing it into
  // nodes and rebuilding them as React elements keeps innerHTML out of the page.
  const parts = useMemo(() => {
    const html = hljs.highlight(text, { language: "c", ignoreIllegals: true }).value;
    const { body } = new DOMParser().parseFromString(html, "text/html");

    return Array.from(body.childNodes, toReact);
  }, [text]);

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

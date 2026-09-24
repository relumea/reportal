import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// The Vite root is web/ (this config's directory). The build output lands
// beside the Python package so ui.py serves it from one directory; Vite would
// keep the previous contents of an out-of-root outDir, so emptyOutDir is set
// explicitly.
const rootDir = fileURLToPath(new URL(".", import.meta.url));
const distDir = fileURLToPath(new URL("../src/reportal/assets/dist", import.meta.url));
const precompressScript = fileURLToPath(
  new URL("../scripts/precompress_spa.py", import.meta.url),
);

/** Order the head so first paint is not gated on the wrong tag: modulepreloads
 * first (vendor/runtime start in parallel with CSS), then the stylesheet with
 * `fetchpriority="high"`, then the entry module.  Vite injects the entry script
 * before its modulepreloads by default; without this, the vendor fetch waits on
 * discovering imports inside the entry chunk. */
function criticalHeadOrder(): Plugin {
  return {
    name: "reportal-critical-head-order",
    transformIndexHtml: {
      order: "post",
      handler(html) {
        const styles: string[] = [];
        const preloads: string[] = [];
        let without = html.replace(
          /\s*<link[^>]*\brel=["']stylesheet["'][^>]*>/gi,
          (tag) => {
            const withPriority = /\bfetchpriority=/.test(tag)
              ? tag.trim()
              : tag.trim().replace(/\/?>$/, ' fetchpriority="high">');
            styles.push(withPriority);
            return "";
          },
        );
        without = without.replace(/\s*<link[^>]*\brel=["']modulepreload["'][^>]*>/gi, (tag) => {
          preloads.push(tag.trim());
          return "";
        });
        if (styles.length === 0 && preloads.length === 0) {
          return html;
        }
        const block = `\n    ${[...preloads, ...styles].join("\n    ")}`;
        if (/<script\b[^>]*\btype=["']module["']/.test(without)) {
          return without.replace(
            /<script\b[^>]*\btype=["']module["'][^>]*>/,
            (script) => `${block}\n    ${script}`,
          );
        }
        return without.replace(/<\/head>/i, `${block}\n  </head>`);
      },
    },
  };
}

/** Write ``.gz`` / ``.br`` siblings after the bundle lands, so a plain
 * ``bun run build`` (not only ``make spa``) ships precompressed assets. */
function precompressDist(): Plugin {
  return {
    name: "reportal-precompress-spa",
    apply: "build",
    closeBundle() {
      execFileSync(process.env.REPORTAL_PYTHON ?? "python3", [precompressScript, distDir], {
        stdio: "inherit",
      });
    },
  };
}

export default defineConfig({
  root: rootDir,
  base: "/static/",
  plugins: [react(), criticalHeadOrder(), precompressDist()],
  build: {
    outDir: "../src/reportal/assets/dist",
    emptyOutDir: true,
    // Release assets must not embed sources or absolute build paths.
    sourcemap: false,
    rollupOptions: {
      output: {
        // React and the router change when the SPA's dependencies change, and
        // the views change on every commit: one vendor chunk keeps a browser's
        // cached copy of the framework across a deploy.  highlight.js serves the
        // lazily loaded function detail view alone, so it stays in that view's
        // chunk instead of loading on every page.
        manualChunks: (id) =>
          id.includes("node_modules") && !id.includes("node_modules/highlight.js/")
            ? "vendor"
            : undefined,
      },
    },
  },
});

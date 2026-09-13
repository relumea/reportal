import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The Vite root is web/ (this config's directory). The build output lands
// beside the Python package so ui.py serves it from one directory; Vite would
// keep the previous contents of an out-of-root outDir, so emptyOutDir is set
// explicitly.
const rootDir = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root: rootDir,
  base: "/static/",
  plugins: [react()],
  build: {
    outDir: "../src/reportal/assets/dist",
    emptyOutDir: true,
  },
});

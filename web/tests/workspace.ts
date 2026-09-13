// Shared paths and environment for the Playwright suite.  Everything is
// resolved from this file's repo root (the nearest ancestor holding
// pyproject.toml), so no machine-specific path is baked in.

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Port `reportal serve` listens on when REPORTAL_E2E_BASE_URL is unset. */
export const DEFAULT_PORT = 8731;

export const SERVER_HOST = "127.0.0.1";

/** Base URL the specs drive; override to reuse a server already running. */
export function baseUrl(): string {
  return process.env.REPORTAL_E2E_BASE_URL ?? `http://${SERVER_HOST}:${DEFAULT_PORT}`;
}

/** Port parsed from `baseUrl()`. */
export function port(): number {
  const url = new URL(baseUrl());
  if (url.port !== "") return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

const REPO_MARKER = "pyproject.toml";
const WORKSPACE_RELATIVE = join(".scratch", "e2e-web");
const PYTHON_RELATIVE = join(".venv", "bin", "python");
const REBREW_RELATIVE = join("rebrew", ".venv", "bin", "rebrew");

const HERE = dirname(fileURLToPath(import.meta.url));

/** Nearest ancestor directory holding pyproject.toml. */
export function repoRoot(): string {
  let current = HERE;
  for (;;) {
    if (existsSync(join(current, REPO_MARKER))) return current;
    const parent = dirname(current);
    if (parent === current) throw new Error(`no ${REPO_MARKER} above ${HERE}`);
    current = parent;
  }
}

/** Scratch workspace the seed writes and the server serves. */
export function workspacePath(): string {
  return join(repoRoot(), WORKSPACE_RELATIVE);
}

/** Interpreter the seed and `reportal serve` run under. */
export function pythonPath(): string {
  return join(repoRoot(), PYTHON_RELATIVE);
}

/** Sibling rebrew CLI the disassembly and decompilation routes call. */
export function rebrewPath(): string {
  return join(dirname(repoRoot()), REBREW_RELATIVE);
}

export function databasePath(): string {
  return join(workspacePath(), "reportal.db");
}

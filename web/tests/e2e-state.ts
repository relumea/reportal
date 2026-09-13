// The run's seed and server state, written by the global setup and read by
// the specs.  A file, not process memory: Playwright forks test workers after
// the setup, and a file survives a worker restart.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { SeedCollection, SeedIds } from "./seed";
import { workspacePath } from "./workspace";

export interface E2eState {
  baseUrl: string;
  port: number;
  /** Process-group leader of `reportal serve`; the teardown kills the group. */
  pid: number;
  workspace: string;
  ids: SeedIds;
  function_name: string;
  collections: SeedCollection[];
  types: string[];
  tag_name: string;
}

const STATE_FILE = "state.json";

export function stateFile(): string {
  return join(workspacePath(), STATE_FILE);
}

export function writeE2eState(state: E2eState): void {
  writeFileSync(stateFile(), `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

let cached: E2eState | undefined;

export function e2eState(): E2eState {
  if (cached === undefined) {
    cached = JSON.parse(readFileSync(stateFile(), "utf8")) as E2eState;
  }
  return cached;
}

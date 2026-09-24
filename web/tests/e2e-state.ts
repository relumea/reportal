// The run's seed and server state, written by the global setup and read by
// the specs.  A file, not process memory: Playwright forks test workers after
// the setup, and a file survives a worker restart.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { SeedCollection, SeedIds, SeedTeam, SimilarPair, StaleRun } from "./seed";
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
  large_binary_id: number;
  large_function_count: number;
  /** The run the seeder left `running`, for the Auto view's recovery control. */
  stale_run: StaleRun;
  /** The team the seeder created, for the upload scope control. */
  team: SeedTeam;
  /** The function pair the Similar functions panel ranks. */
  similar: SimilarPair;
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

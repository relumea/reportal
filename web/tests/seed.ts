// The seed helper: runs the Python seeder (which reuses the SPA smoke's
// workspace builder) and returns the ids and collections it produced.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { pythonPath, repoRoot, workspacePath } from "./workspace";

export interface SeedIds {
  binary_id: number;
  analysis_id: number;
  function_id: number;
  candidate_function_id: number;
  conversation_id: number;
}

export interface SeedCollection {
  id: number;
  name: string;
}

/** One seed run's result, as tools/seed_e2e.py prints it. */
export interface SeedResult {
  workspace: string;
  ids: SeedIds;
  /** First seeded function's name; the functions table's marker. */
  function_name: string;
  collections: SeedCollection[];
  /** Names of the stored data types the Data types panel lists. */
  types: string[];
  /** Tag applied to the seeded binary; the search modal's tag query uses it. */
  tag_name: string;
  /** A binary whose function list is long enough for the table to window. */
  large_binary_id: number;
  /** How many functions it holds, so a spec can name the last row. */
  large_function_count: number;
  /** A run on that binary a dead process left `running`, for the recovery control. */
  stale_run: StaleRun;
  /** The team an upload can be registered into. */
  team: SeedTeam;
}

/** A team the seeder created, so a scope control has a real choice. */
export interface SeedTeam {
  id: number;
  name: string;
}

/** The run the seeder leaves `running` so the Auto view's recovery is reachable. */
export interface StaleRun {
  binary_id: number;
  run_id: number;
  tasks: number;
}

const SEED_SCRIPT_RELATIVE = join("tools", "seed_e2e.py");
const MAX_SEED_OUTPUT_BYTES = 8 * 1024 * 1024;
const INSTALL_HINT = 'uv venv .venv && uv pip install -e ".[dev]" --python .venv/bin/python';

export function seedWorkspace(): SeedResult {
  const python = pythonPath();
  if (!existsSync(python)) {
    throw new Error(`missing ${python}; install the workspace venv with: ${INSTALL_HINT}`);
  }
  const script = join(repoRoot(), SEED_SCRIPT_RELATIVE);
  const output = execFileSync(python, [script, "--workspace", workspacePath()], {
    cwd: repoRoot(),
    encoding: "utf8",
    maxBuffer: MAX_SEED_OUTPUT_BYTES,
  });
  const lastLine = output
    .split("\n")
    .filter((line) => line.trim() !== "")
    .at(-1);
  if (lastLine === undefined) throw new Error("tools/seed_e2e.py printed no state");
  return JSON.parse(lastLine) as SeedResult;
}

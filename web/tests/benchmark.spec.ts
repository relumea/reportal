// The benchmark panel: the empty reading before any run, the partner select and
// the run control it enables.  A run is not clicked here: it would replace the
// seeded binary's recorded matches, which the other specs read.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the benchmark panel reads empty and offers a partner", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=provenance`);
  const panel = panelByTitle(page, "Benchmark");
  await expect(panel).toBeVisible();

  await expect(panel.getByText(/Nothing measured yet/)).toBeVisible();

  // The run needs a partner, so the control is disabled until one is picked.
  const partner = panel.getByLabel("Partner");
  await expect(partner).toHaveValue("");
  await expect(panel.getByRole("button", { name: "Run benchmark" })).toBeDisabled();

  // The seeded workspace holds a second binary, which is the only candidate.
  await partner.selectOption({ index: 1 });
  await expect(partner).not.toHaveValue("");
  await expect(panel.getByRole("button", { name: "Run benchmark" })).toBeEnabled();
});

test("the rename half names the input it is missing", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=provenance`);
  const panel = panelByTitle(page, "Benchmark");
  await expect(panel.getByRole("heading", { name: "Rename proposals" })).toBeVisible();

  // No debug symbol file named a function of the seeded binary, so the read
  // answers 200 with the reason and the command that supplies the ground truth.
  await expect(panel.getByText(/reportal symbols/)).toBeVisible();
});

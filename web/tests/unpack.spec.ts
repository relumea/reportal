// The unpack panel: the empty provenance the seeded binary reads, the packer
// select and the rebuild control.  A run is not clicked here: the seeded binary
// carries no packer signature, so it would answer a refusal, and the e2e fixture
// fails a spec that gets an error response on purpose.  The refusal paths are
// covered by tests/test_unpack.py.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("packer detection shows a per-section entropy strip", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=format`);
  const packer = panelByTitle(page, "Packer Detection");
  await expect(packer.locator(".entropy-strip")).toBeVisible();
  await expect(packer.locator(".entropy-strip-cell").first()).toHaveAttribute("title", /bits\/byte|unavailable/);
});

test("the unpack panel reads empty and offers the packer choice", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=format`);
  const panel = panelByTitle(page, "Unpacked Files");
  await expect(panel).toBeVisible();

  // Nothing was unpacked from the seeded binary, so the panel says so and names
  // what an unpack reads, rather than showing an empty provenance table.
  await expect(panel.getByText(/^Not unpacked\./)).toBeVisible();

  // Auto leaves the packer to the file's own stub; the other options pin one.
  const packer = panel.getByLabel("Packer");
  await expect(packer).toHaveValue("");
  await packer.selectOption("lzexe");
  await expect(packer).toHaveValue("lzexe");
  await expect(panel.getByRole("button", { name: "Run unpack" })).toBeEnabled();
});

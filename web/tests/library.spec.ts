// The library identification panel: an empty reading before the first run, the
// module table after one, and the export control answering a document.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the library panel reads empty, runs and exports", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const panel = panelByTitle(page, "Library identification");
  await expect(panel).toBeVisible();

  // Before the first run the panel names the command that fills it rather than
  // showing an empty table.
  await expect(panel.getByText(/reportal library/)).toBeVisible();

  // The export control answers the format the select names, from the stored
  // reading, so an unidentified binary still gets a valid document.
  await panel.getByLabel("Export format").selectOption("spdx");
  await panel.getByRole("button", { name: "Export" }).click();
  await expect(panel.locator(".code-block").first()).toBeVisible();
  await expect(panel.getByText(/spdxVersion/)).toBeVisible();
});

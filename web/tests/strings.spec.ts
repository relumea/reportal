// The Strings panel: a string's identity is its address, so clicking one opens
// the Functions view filtered to the functions that reference it, and the
// filter state lands in the URL hash.  The engine computes the references, so
// the first assertion has a generous timeout.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("clicking a string opens the functions that reference it", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const strings = panelByTitle(page, "Strings");
  await strings.getByRole("button", { name: "Load strings" }).click();
  await expect(strings.locator("table.data-table tbody tr").first()).toBeVisible({
    timeout: 60_000,
  });

  const link = strings.locator('a[href*="refers_to="]').first();
  await expect(link).toBeVisible();
  await link.click();

  await expect(page).toHaveURL(/refers_to=/);
  const functions = panelByTitle(page, "Functions");
  await expect(functions.getByText(/Referrers of /)).toBeVisible({ timeout: 60_000 });
  // Either the filter kept rows or it says plainly that nobody references it.
  await expect(
    functions.getByText(/of \d+ functions|No function references/),
  ).toBeVisible();
});

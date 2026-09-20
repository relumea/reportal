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
  await expect(strings.getByPlaceholder(/Search \d+ strings/)).toBeVisible();

  const row = strings.locator("table.data-table tbody tr").first();
  await expect(row.locator('a[href*="refers_to="]').first()).toBeVisible();
  await row.click();

  await expect(page).toHaveURL(/refers_to=/);
  const functions = panelByTitle(page, "Functions");
  await expect(functions.getByText(/Referrers of /)).toBeVisible({ timeout: 60_000 });
  await expect(functions.locator(".chip").filter({ hasText: /Referrers of / })).toBeVisible();
  // Either the filter kept rows or it says plainly that nobody references it.
  await expect(
    functions.getByText(/of \d+ functions|No function references/),
  ).toBeVisible();
});

// The Collections view's list controls: the scope filter in the hash, the sort
// that includes the owner, and the owner column.  The seeded workspace has no
// teams, so every collection it holds is personal and the team scope is the one
// filter that matches nothing, which is what makes the empty state checkable.

import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

test("the scope filter and the owner sort drive the collection list", async ({ page }) => {
  await page.goto("/#/collections");
  const panel = panelByTitle(page, "Collections");
  const rows = panel.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  await expect(panel.getByRole("columnheader", { name: "Owner" })).toBeVisible();
  const total = await rows.count();
  expect(total).toBeGreaterThan(0);

  // A scope with no match says so rather than reading as an empty register.
  await panel.getByLabel("Workspace").selectOption("team");
  await expect(page).toHaveURL(/workspace=team/);
  await expect(panel.getByText("No collections match this filter", { exact: false })).toBeVisible();

  // Every seeded collection is personal, so the personal scope is the whole list.
  await panel.getByLabel("Workspace").selectOption("personal");
  await expect(page).toHaveURL(/workspace=personal/);
  await expect(rows).toHaveCount(total);

  // The sort control is in the hash too, and the route echoes the order it
  // applied, so the table is the server's ordering rather than the browser's.
  await panel.getByLabel("Sort").selectOption("owner");
  await expect(page).toHaveURL(/order=owner/);
  await expect(rows).toHaveCount(total);

  // The controls survive a reload, which is what keeping them in the hash buys.
  await page.reload();
  await expect(panel.getByLabel("Workspace")).toHaveValue("personal");
  await expect(rows).toHaveCount(total);
});

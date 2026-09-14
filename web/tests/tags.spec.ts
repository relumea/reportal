// The Tags view: the register's tag vocabulary with what carries each tag, and
// the two maintenance writes.  The seeded workspace applies one tag to the
// seeded binary, so the list has a row to rename and delete.

import { panelByTitle, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

test("a tag is renamed everywhere and then deleted", async ({ page }) => {
  const name = uniqueName("e2e-tag");
  const renamed = `${name}-renamed`;

  // Create the tag where tags are created: on a binary's Tags panel.
  await page.goto("/#/tags");
  const panel = panelByTitle(page, "Tags");
  await expect(panel.locator("tbody tr").first()).toBeVisible();

  await page.goto(`/#/binaries/1`);
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(tags.getByRole("cell", { name, exact: true })).toBeVisible();

  // The new tag is listed with the binary that carries it, and selecting the
  // row opens the panel that renames or deletes it.
  await page.goto("/#/tags");
  const row = panel.locator("tbody tr").filter({ hasText: name }).first();
  await expect(row).toBeVisible();
  await expect(row).toContainText("1");
  await row.click();
  const detail = panelByTitle(page, `Tag ${name}`);
  await detail.getByLabel("Name").fill(renamed);
  await detail.getByRole("button", { name: "Save" }).click();
  await expect(panel.locator("tbody tr").filter({ hasText: renamed }).first()).toBeVisible();
  await expect(panel.getByText(name, { exact: true })).toHaveCount(0);

  // The panel stays open across the rename, so the delete is one click away;
  // clicking the row again would close it, which is the view's toggle.
  const renamedDetail = panelByTitle(page, `Tag ${renamed}`);
  await expect(renamedDetail).toBeVisible();
  await renamedDetail.getByRole("button", { name: "Delete" }).click();
  await renamedDetail.getByRole("button", { name: "Delete" }).click();
  await expect(panel.locator("tbody tr").filter({ hasText: renamed })).toHaveCount(0);

  await page.goto("/#/binaries/1");
  await expect(panelByTitle(page, "Tags").getByText(renamed, { exact: true })).toHaveCount(0);
});

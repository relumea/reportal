// The Data types panel's history section: a rename records a version with its
// per-field diff, and a revert restores the previous state.

import type { Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// A manually authored struct, so a rename does not disturb the source column a
// scan-imported row carries, and the revert puts the seeded name back.
const TYPE_NAME = "NP_ENTRY";

// A rename target must be a C identifier, so the unique suffix drops the
// helper's hyphens.
function renamedType(): string {
  return uniqueName("e2e_type").replaceAll("-", "_");
}

function panelTypes(page: Page) {
  return panelByTitle(page, "Data types");
}

test("a rename records a version the panel can revert", async ({ page }) => {
  const renamed = renamedType();
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  const card = types.locator(".card").filter({ hasText: TYPE_NAME }).first();
  await expect(card).toBeVisible();
  await card.getByLabel("Rename", { exact: true }).fill(renamed);
  await card.getByRole("button", { name: "Rename type" }).click();
  await expect(types.getByText(renamed, { exact: false }).first()).toBeVisible();

  // Reload so the history section loads the version the rename recorded.
  await page.reload();
  const renamedCard = types.locator(".card").filter({ hasText: renamed }).first();
  await renamedCard.getByRole("button", { name: "History", exact: true }).click();

  const versions = types.locator(".type-history > li");
  await expect(versions).toHaveCount(1);
  await expect(versions.first()).toContainText("name");
  await expect(versions.first()).toContainText(TYPE_NAME);
  await expect(versions.first()).toContainText(renamed);
  await expect(types.getByText("1 recorded edit", { exact: false })).toBeVisible();

  await versions.first().getByRole("button", { name: "Revert" }).click();
  await versions.first().getByRole("button", { name: "Revert" }).click();

  // The revert refreshes the model, so the renamed card carries the seeded name
  // again (the refresh remounts the cards, which is why the assertion is on the
  // model rather than on the section's own status line).
  const restoredCard = types.locator(".card").filter({ hasText: TYPE_NAME }).first();
  await expect(restoredCard).toBeVisible();

  // The revert recorded its own inverse, so the history now lists two versions.
  await restoredCard.getByRole("button", { name: "History", exact: true }).click();
  await expect(types.locator(".type-history > li")).toHaveCount(2);
  await expect(types.locator(".type-history > li").first()).toContainText("revert");
  await expect(types.locator(".type-history > li").first()).toContainText(TYPE_NAME);
});

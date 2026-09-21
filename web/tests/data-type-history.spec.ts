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
  return panelByTitle(page, "Data Types");
}

test("a rename records a version the panel can revert", async ({ page }) => {
  const renamed = renamedType();
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  // The card title names only the card's own type; member tables in the
  // body mention other types, so a bare card-text filter would match them.
  const card = types
    .locator(".card")
    .filter({ has: page.locator(".card-title", { hasText: TYPE_NAME }) })
    .first();
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
  // Hosted history attributes each version: the named user and how long ago.
  await expect(versions.first()).toContainText(/manual.*just now/);
  await expect(versions.first()).toContainText(TYPE_NAME);
  await expect(versions.first()).toContainText(renamed);
  await expect(types.getByText("1 recorded edit", { exact: false })).toBeVisible();
  await expect(versions.first().getByText("Current", { exact: true })).toBeVisible();

  await versions.first().getByRole("button", { name: "Revert" }).click();
  await versions.first().getByRole("button", { name: "Revert" }).click();

  // The revert refreshes the model, so the renamed card carries the seeded name
  // again. Reload for a settled tree: the refresh remounts the cards, and a
  // History click on the stale instance would toggle a detached section.
  await page.reload();
  const restoredCard = types
    .locator(".card")
    .filter({ has: page.locator(".card-title", { hasText: TYPE_NAME }) })
    .first();
  await expect(restoredCard).toBeVisible();

  // The revert recorded its own inverse, so the history now lists two versions.
  await restoredCard.getByRole("button", { name: "History", exact: true }).click();
  await expect(types.locator(".type-history > li")).toHaveCount(2);
  await expect(types.locator(".type-history > li").first()).toContainText("Current");
  await expect(types.locator(".type-history > li").last()).toContainText("Original");
  await expect(types.locator(".type-history > li").first()).toContainText("revert");
  await expect(types.locator(".type-history > li").first()).toContainText(TYPE_NAME);
});

test("a member save shows in the history without a reload", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);
  const card = types
    .locator(".card")
    .filter({ has: page.locator(".card-title", { hasText: "NP_HEADER" }) })
    .first();
  await expect(card).toBeVisible();
  await card.getByRole("button", { name: "History", exact: true }).click();
  const rows = card.locator(".type-history > li");
  const before = await rows.count();

  // A no-op save records nothing, so retype the member and restore it after.
  const member = card
    .getByLabel("Type of member flags", { exact: true })
    .locator("xpath=ancestor::tr");
  await card.getByLabel("Type of member flags", { exact: true }).fill("int");
  await member.getByRole("button", { name: "Save", exact: true }).click();
  // The save remounts the card with the section closed; reopening it must show
  // the version the save wrote, not the cached empty list from the mount.
  const saved = types
    .locator(".card")
    .filter({ has: page.locator(".card-title", { hasText: "NP_HEADER" }) })
    .first();
  await saved.getByRole("button", { name: "History", exact: true }).click();
  const poll = (): Promise<number> => saved.locator(".type-history > li").count();
  await expect.poll(poll).toBeGreaterThan(before);

  const restored = types
    .locator(".card")
    .filter({ has: page.locator(".card-title", { hasText: "NP_HEADER" }) })
    .first();
  await restored.getByLabel("Type of member flags", { exact: true }).fill("unsigned int");
  await restored
    .getByLabel("Type of member flags", { exact: true })
    .locator("xpath=ancestor::tr")
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(restored.getByLabel("Type of member flags", { exact: true })).toHaveValue(
    "unsigned int",
  );
});

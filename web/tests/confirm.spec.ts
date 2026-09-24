// The destructive controls behind an inline confirmation: cancel leaves the
// state exactly as it was, and confirm performs the change.

import type { Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();
const TAG_CONFIRM_MESSAGE = /^Remove tag e2e-confirm-.*\?$/;
const BULK_CONFIRM_MESSAGE = "Delete 1 selected binary?";

async function addTag(page: Page, name: string): Promise<void> {
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(rowContaining(tags, name)).toBeVisible();
}

test("cancelling the tag delete keeps the tag and confirming removes it", async ({ page }) => {
  const name = uniqueName("e2e-confirm");
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=review`);
  await addTag(page, name);

  const tags = panelByTitle(page, "Tags");
  const row = rowContaining(tags, name);
  await row.getByRole("button", { name: "Remove" }).click();
  await expect(tags.getByText(TAG_CONFIRM_MESSAGE)).toBeVisible();
  await row.getByRole("button", { name: "Cancel" }).click();
  await expect(tags.getByText(TAG_CONFIRM_MESSAGE)).toHaveCount(0);
  await expect(row).toBeVisible();

  await row.getByRole("button", { name: "Remove" }).click();
  await expect(tags.getByText(TAG_CONFIRM_MESSAGE)).toBeVisible();
  await row.getByRole("button", { name: "Remove" }).click();
  await expect(rowContaining(tags, name)).toHaveCount(0);
});

test("cancelling the bulk delete leaves the binary in the list", async ({ page }) => {
  await page.goto("/#/binaries");
  const bulk = panelByTitle(page, "Bulk actions");
  await page.getByLabel("select notepad.exe", { exact: true }).check();
  await bulk.getByRole("button", { name: "Delete" }).click();
  await expect(bulk.getByText(BULK_CONFIRM_MESSAGE)).toBeVisible();
  await bulk.getByRole("button", { name: "Cancel" }).click();
  await expect(bulk.getByText(BULK_CONFIRM_MESSAGE)).toHaveCount(0);
  await expect(
    page.locator("table.data-table tbody tr").filter({ hasText: "notepad.exe" }),
  ).toBeVisible();
});

test("confirming the bulk delete removes the selected binary", async ({ page }) => {
  const filename = `${uniqueName("e2e-binary")}.bin`;
  await page.goto("/#/binaries");
  await page.locator('input[type="file"]').first().setInputFiles({
    name: filename,
    mimeType: "application/octet-stream",
    buffer: Buffer.from(filename),
  });
  await page.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(page.getByText(`Uploaded ${filename} as binary #`)).toBeVisible();

  await page.getByLabel(`select ${filename}`, { exact: true }).check();
  const bulk = panelByTitle(page, "Bulk actions");
  await bulk.getByRole("button", { name: "Delete" }).click();
  await expect(bulk.getByText(BULK_CONFIRM_MESSAGE)).toBeVisible();
  await bulk.getByRole("button", { name: "Delete" }).click();
  await expect(
    page.locator("table.data-table tbody tr").filter({ hasText: filename }),
  ).toHaveCount(0);
});

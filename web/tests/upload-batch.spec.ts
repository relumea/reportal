// The batch upload control: one row per file with its own options, per-file
// tags, the collection picker and the duplicate answer.

import { panelByTitle, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

function fileUpload(name: string): { name: string; mimeType: string; buffer: Buffer } {
  return { name, mimeType: "application/octet-stream", buffer: Buffer.from(name) };
}

test("a batch upload lists each file, applies its tag and reports each result", async ({ page }) => {
  const first = `${uniqueName("e2e-batch-a")}.bin`;
  const second = `${uniqueName("e2e-batch-b")}.bin`;
  const tag = uniqueName("e2e-batch-tag");

  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");
  await page.locator('input[type="file"]').setInputFiles([fileUpload(first), fileUpload(second)]);
  await expect(panel.getByText("2 selected for upload")).toBeVisible();
  await expect(panel.locator("table.data-table tbody tr")).toHaveCount(2);

  const firstRow = panel.locator("table.data-table tbody tr").first();
  await firstRow.getByLabel("Tag", { exact: true }).fill(tag);
  await firstRow.getByLabel("Tag", { exact: true }).press("Enter");
  await expect(firstRow.getByText(tag)).toBeVisible();

  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Uploaded ${first} as binary #`)).toBeVisible();
  await expect(panel.getByText(`Uploaded ${second} as binary #`)).toBeVisible();
  await expect(panel.getByText(`Tags: ${tag}.`)).toBeVisible();
  await expect(panel.getByText("2 file(s): 0 already stored, 0 refused.")).toBeVisible();

  // The upload list clears and the new binaries join the table.
  await expect(
    page.locator("table.data-table tbody tr").filter({ hasText: first }),
  ).toBeVisible();
});

test("a duplicate is reported as already stored, not as a failure", async ({ page }) => {
  const name = `${uniqueName("e2e-dup")}.bin`;

  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");

  await page.locator('input[type="file"]').setInputFiles(fileUpload(name));
  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Uploaded ${name} as binary #`)).toBeVisible();

  // The same bytes again: the response reports the stored row.
  await page.locator('input[type="file"]').setInputFiles(fileUpload(name));
  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Already stored ${name} as binary #`)).toBeVisible();
  await expect(panel.getByText("1 file(s): 1 already stored, 0 refused.")).toBeVisible();
});

test("the drop zone accepts a file and Configure all reaches every row", async ({ page }) => {
  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");

  // Dropping a file queues it with the automatic plan, which the row badges.
  await panel.locator(".drop-zone").evaluate((node) => {
    const file = new File([new Uint8Array([77, 90, 0, 0])], "dropped.bin", {
      type: "application/octet-stream",
    });
    const transfer = new DataTransfer();
    transfer.items.add(file);
    node.dispatchEvent(new DragEvent("drop", { bubbles: true, dataTransfer: transfer }));
  });
  await expect(panel.getByText("1 selected for upload")).toBeVisible();
  await expect(panel.getByText("auto", { exact: true })).toBeVisible();

  // Configure all applies one value to the queued rows and replaces the badge.
  await panel.getByLabel("ISA for every file").selectOption("x86_32");
  await expect(panel.getByText("auto / x86_32", { exact: true })).toBeVisible();
  await expect(panel.getByText("auto", { exact: true })).toBeHidden();
  await expect(panel.getByLabel("ISA for dropped.bin")).toHaveValue("x86_32");
});

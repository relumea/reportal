// The batch upload control: one row per file with its own options, per-file
// tags, the collection picker and the duplicate answer.

import { e2eState } from "./e2e-state";
import { panelByTitle, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

function fileUpload(name: string): { name: string; mimeType: string; buffer: Buffer } {
  return { name, mimeType: "application/octet-stream", buffer: Buffer.from(name) };
}

test("a batch upload lists each file, applies its tag and reports each result", async ({ page }) => {
  const first = `${uniqueName("e2e-batch-a")}.bin`;
  const second = `${uniqueName("e2e-batch-b")}.bin`;
  const tag = uniqueName("e2e-batch-tag");

  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");
  await page.locator('input[type="file"][name="file"]').setInputFiles([fileUpload(first), fileUpload(second)]);
  await expect(panel.getByText("2 selected for upload")).toBeVisible();
  await expect(panel.locator("table.data-table tbody tr")).toHaveCount(2);
  await expect(panel.locator(".copy-row").first()).toBeVisible();

  const firstRow = panel.locator("table.data-table tbody tr").first();
  await expect(firstRow.getByLabel(`debug symbols for ${first}`)).toHaveCount(1);
  await firstRow.getByLabel("Tag", { exact: true }).fill(tag);
  await firstRow.getByLabel("Tag", { exact: true }).press("Enter");
  await expect(firstRow.getByText(tag)).toBeVisible();

  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Uploaded ${first} as binary #`)).toBeVisible();
  await expect(panel.getByText(`Uploaded ${second} as binary #`)).toBeVisible();
  await expect(panel.getByText(`Tags: ${tag}.`)).toBeVisible();
  await expect(panel.getByText("2 file(s): 0 already stored, 0 refused.")).toBeVisible();

  const archive = panelByTitle(page, "Extract an archive").locator("select").first();
  await archive.selectOption({ label: first });
  await expect(archive).not.toHaveValue("");
  const reference = panelByTitle(page, "Malware families").locator("select").first();
  await reference.selectOption({ label: second });

  // The upload list clears and the new binaries join the table.
  await expect(
    page.locator("table.data-table tbody tr").filter({ hasText: first }),
  ).toBeVisible();
});

test("extraction validation stays beside the archive controls", async ({ page }) => {
  await page.goto("/#/binaries");
  const upload = panelByTitle(page, "Upload binaries");
  const extract = panelByTitle(page, "Extract an archive");
  await extract.getByRole("button", { name: "Extract", exact: true }).click();
  await expect(extract.getByRole("alert")).toContainText("Select a stored archive above.");
  await expect(upload.getByRole("alert")).toHaveCount(0);

  await page.locator('input[type="file"][name="file"]').setInputFiles(fileUpload("queued.bin"));
  await expect(extract.getByRole("alert")).toContainText("Select a stored archive above.");
  await expect(upload.getByRole("alert")).toHaveCount(0);
  await expect(upload.getByRole("button", { name: "Extract" })).toHaveCount(0);

  await page.locator('input[type="file"][name="file"]').setInputFiles(fileUpload("queued.zip"));
  await expect(upload.getByLabel("extract queued.zip")).toBeVisible();
});

test("a duplicate is reported as already stored, not as a failure", async ({ page }) => {
  const name = `${uniqueName("e2e-dup")}.bin`;

  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");

  await page.locator('input[type="file"][name="file"]').setInputFiles(fileUpload(name));
  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Uploaded ${name} as binary #`)).toBeVisible();

  // The same bytes again: the response reports the stored row.
  await page.locator('input[type="file"][name="file"]').setInputFiles(fileUpload(name));
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
  await expect(panel.getByText("auto / x86_32 / auto", { exact: true })).toBeVisible();
  await expect(panel.getByText("auto", { exact: true })).toBeHidden();
  await expect(panel.getByLabel("ISA for dropped.bin")).toHaveValue("x86_32");
});

test("an upload can be registered into a team's scope", async ({ page }) => {
  const name = `${uniqueName("e2e-scoped")}.bin`;

  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Upload binaries");
  await page.locator('input[type="file"][name="file"]').setInputFiles(fileUpload(name));

  // Configure all reaches the scope column the same way it reaches the plan.
  await panel.getByLabel("Scope for every file").selectOption(String(state.team.id));
  await expect(panel.getByLabel(`scope for ${name}`)).toHaveValue(String(state.team.id));

  await panel.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(panel.getByText(`Uploaded ${name} as binary #`)).toBeVisible();
  await expect(panel.getByText(`Team #${state.team.id} scope.`)).toBeVisible();
});

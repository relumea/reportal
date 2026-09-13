// The Bulk Transfer dialog against the seeded workspace: one row's name is
// transferred, the preview writes nothing, and the transfer renames the source
// function to the chosen candidate's name.

import type { Locator } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

/** The first dialog row whose name diff actually changes the source name. */
async function pickChangingRow(dialog: Locator): Promise<{ row: Locator; candidate: string }> {
  const rows = dialog.locator("table.data-table tbody tr");
  const count = await rows.count();
  for (let index = 0; index < count; index += 1) {
    const row = rows.nth(index);
    const text = await row.locator(".mono").innerText();
    const [left, right] = text.split("<-").map((part) => part.trim());
    if (left && right && left !== right) return { row, candidate: right };
  }
  throw new Error("no dialog row changes the source name");
}

test("a bulk name transfer previews without writing and then renames", async ({ page }) => {
  await page.goto("/#/matches");
  await page.getByLabel("Function", { exact: true }).fill(String(state.ids.function_id));
  await page.getByRole("button", { name: "Load", exact: true }).click();
  await expect(page.getByText("2 candidates recorded", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Bulk transfer" }).click();
  // The dialog is nested inside the match view's own panel, so the innermost
  // panel carrying that heading is the dialog itself.
  const dialog = panelByTitle(page, "Bulk transfer").last();
  const { row, candidate } = await pickChangingRow(dialog);
  const sourceName = (await row.locator(".mono").innerText()).split("<-")[0]?.trim() ?? "";
  expect(sourceName).not.toEqual(candidate);

  // Names start ticked where the match differs; keep only the chosen row.
  await dialog.getByLabel("All names").uncheck();
  await row.getByLabel("Names").check();

  await dialog.getByRole("button", { name: "Preview" }).click();
  await expect(
    dialog.getByText("Preview: 1 applied, 0 skipped, 0 failed of 1.", { exact: false }),
  ).toBeVisible();
  // The preview wrote nothing, so the row still reads its original name.
  await expect(row.locator(".mono")).toHaveText(`${sourceName} <- ${candidate}`);

  const transferred = page.waitForResponse(
    (response) =>
      response.url().includes("/matches/transfer") &&
      response.request().method() === "POST" &&
      response.ok(),
  );
  await dialog.getByRole("button", { name: "Transfer" }).click();
  const report = (await (await transferred).json()) as { journal_action?: string };
  await expect(dialog.getByText("1 applied, 0 skipped, 0 failed of 1.", { exact: false })).toBeVisible();
  // The transfer renamed the source function to the candidate's name.
  await expect(dialog.getByText(`${candidate} <- ${candidate}`, { exact: false })).toBeVisible();

  // The suite shares one seeded workspace, so undo the rename through the
  // action's own journal entry before later specs run.
  expect(report.journal_action).toBeTruthy();
  const revert = await page.request.post("/api/journal/revert", {
    data: { action: report.journal_action },
  });
  expect(revert.ok()).toBeTruthy();
  const outcome = (await revert.json()) as { reverted: number; failed: number };
  expect(outcome.failed).toBe(0);
  expect(outcome.reverted).toBeGreaterThan(0);
});

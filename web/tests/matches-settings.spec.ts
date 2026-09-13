// The Match Settings sheet: applying a platform scope and running the match
// changes the recorded row set.  Android is the scope because no binary in the
// seeded workspace is an Android module, so the candidate corpus empties and
// the result is deterministic.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("a platform scope narrows the recorded match rows to none", async ({ page }) => {
  await page.goto("/#/matches");
  await page.getByLabel("Function", { exact: true }).fill(String(state.ids.function_id));
  await page.getByRole("button", { name: "Load", exact: true }).click();

  // The seeded workspace recorded both edges of the pair.
  await expect(page.getByText("2 candidates recorded", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Match settings" }).click();
  // The sheet is nested inside the match view's own panel, so the innermost
  // panel carrying that heading is the sheet itself.
  const sheet = panelByTitle(page, "Match settings").last();
  await sheet.getByLabel("Android", { exact: true }).check();
  const runResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/match") &&
      response.request().method() === "POST" &&
      response.ok(),
  );
  await sheet.getByRole("button", { name: "Run match" }).click();
  const run = (await (await runResponse).json()) as { journal_action?: string };

  await expect(page.getByText("Match run recorded:", { exact: false })).toBeVisible();
  await expect(page.getByText("0 candidates recorded", { exact: false })).toBeVisible();
  await expect(page.getByText("No matches recorded for this binary.", { exact: false })).toBeVisible();

  // The active scope shows as a chip the reader can clear.
  await expect(page.locator(".chip").getByText("Android", { exact: true })).toBeVisible();
  await page.locator(".chip").getByLabel("Clear Android").click();
  await expect(page.locator(".chip").getByText("Android", { exact: true })).toHaveCount(0);

  // The suite shares one seeded workspace, so undo the run through its own
  // journal entry and leave the seeded rows behind for later specs.
  expect(run.journal_action).toBeTruthy();
  const revert = await page.request.post("/api/journal/revert", {
    data: { action: run.journal_action },
  });
  expect(revert.ok()).toBeTruthy();
  const outcome = (await revert.json()) as { reverted: number; failed: number };
  expect(outcome.failed).toBe(0);
  expect(outcome.reverted).toBeGreaterThan(0);
});

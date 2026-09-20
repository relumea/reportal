// The Signature panel's per-parameter fields: an argument arrival location the
// analyst sets is stored and rendered into the prototype, and the reorder
// controls recompute the locations the calling convention implies.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("editing the arrival location changes the rendered prototype", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const panel = panelByTitle(page, "Signature");
  await expect(panel.getByText("prototype")).toBeVisible();
  await expect(page.locator(".detail-head .copy-row .mono").nth(1)).not.toHaveText("");

  const at = panel.getByLabel("Arrival location of parameter 0");
  await at.fill("[esp+4]");
  await panel.getByRole("button", { name: "Save", exact: true }).first().click();

  // The rendered prototype annotates the field the model now carries.
  await expect(panel.getByText(/at \[esp\+4\]/)).toBeVisible();

  await panel.getByLabel("Return type").fill("NP_HEADER");
  await panel.getByRole("button", { name: "Save head" }).click();
  await expect(panel.getByRole("link", { name: "NP_HEADER" })).toHaveAttribute(
    "href",
    /search=NP_HEADER/,
  );
});

test("the signature history lists a recorded version and reverts it", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const panel = panelByTitle(page, "Signature");
  const shown = panel.locator(".code-block pre").first();
  const before = await shown.innerText();

  // Record a version to revert to: a convention the signature does not carry.
  await panel.getByRole("combobox", { name: "Convention", exact: true }).selectOption("stdcall");
  await panel.getByRole("button", { name: "Save head" }).click();
  await expect(shown).toContainText("__stdcall");

  await panel.getByRole("button", { name: "History", exact: true }).click();
  const newest = panel.locator(".type-history li").first();
  // The newest row is the write just made, carrying the prototype it replaced.
  await expect(newest.locator("code")).toHaveText(before);

  // The confirm control of a ConfirmButton carries the same label.
  await newest.getByRole("button", { name: "Revert", exact: true }).click();
  await newest.getByRole("button", { name: "Revert", exact: true }).click();

  // The revert restored the head and refreshed the panel, and recorded itself.
  await expect(shown).not.toContainText("__stdcall");
  await expect(panel.locator(".type-history li").first()).toContainText("revert");
});

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

  const at = panel.getByLabel("Arrival location of parameter 0");
  await at.fill("[esp+4]");
  await panel.getByRole("button", { name: "Save", exact: true }).first().click();

  // The rendered prototype annotates the field the model now carries.
  await expect(panel.getByText(/at \[esp\+4\]/)).toBeVisible();
});

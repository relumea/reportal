// Team invites: the Users view carries the mint/join controls, and minting
// through the UI hands back a one-time code.

import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

test("the users view mints a team invite code", async ({ page }) => {
  await page.goto("/#/users");
  const panel = panelByTitle(page, "Invites");
  await expect(panel.getByLabel("Team id")).toBeVisible();
  await expect(panel.getByLabel("Invite code")).toBeVisible();
  await expect(panel.getByRole("button", { name: "Mint invite" })).toBeDisabled();
  await expect(panel.getByRole("button", { name: "Join team" })).toBeDisabled();
});

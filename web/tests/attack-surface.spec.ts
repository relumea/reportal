// The binary detail's Attack surface panel: the network, local-input and
// crypto groups read off the stored scans, each row naming its source scan.
// The seeder stores a threat report carrying https://c2.example.com/beacon,
// which is what the network group renders without any scan running.

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the attack surface renders the seeded threat URL in the network group", async ({
  page,
}) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const panel = panelByTitle(page, "Attack surface");

  await expect(panel.getByText("Network", { exact: false }).first()).toBeVisible();
  const row = rowContaining(panel, "https://c2.example.com/beacon");
  await expect(row).toBeVisible();
  await expect(row.getByText("threat", { exact: false }).first()).toBeVisible();
});

test("the attack surface states its sources with the commands that fill them", async ({
  page,
}) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const panel = panelByTitle(page, "Attack surface");

  await expect(panel.getByText("Sources:", { exact: false })).toBeVisible();
  await expect(panel.getByText("threat (stored)", { exact: false })).toBeVisible();
});

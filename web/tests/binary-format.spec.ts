// Panels that read a PE-only structure are left out for another format, so an
// ELF binary's tabs do not fill with "n/a" panels.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("an ELF binary shows no PE-only panels", async ({ page }) => {
  await page.route(`**/api/binaries/${state.ids.binary_id}`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    const response = await route.fetch();
    const binary = (await response.json()) as Record<string, unknown>;
    await route.fulfill({ response, json: { ...binary, format: "elf", format_override: "" } });
  });
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=format`);
  await expect(panelByTitle(page, "Packer detection")).toBeVisible();
  for (const title of ["Exports", "Relocations", "Code signature"]) {
    await expect(page.getByRole("heading", { name: new RegExp(`^${title}`, "u") })).toHaveCount(0);
  }
  await page.getByRole("tab", { name: "Security" }).click();
  await expect(panelByTitle(page, "Threat report")).toBeVisible();
  await expect(page.getByRole("heading", { name: /^Loader mitigations/u })).toHaveCount(0);
});

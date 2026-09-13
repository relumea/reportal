// The panels added for the hosted portal's Memory and Data types surfaces:
// a real byte window read on demand, and the stored type list's filter.
// Both assert the rendered state, not just that the panel exists.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// A type the seeder stores under this name, so the filter has a needle that
// matches exactly one row whatever else the workspace holds.
const FILTER_TARGET = "NP_ENTRY";

test("a file-offset read renders the window's own bytes", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const memory = panelByTitle(page, "Memory");

  // A read needs an address, and the refusal is visible on the control.
  const read = memory.getByRole("button", { name: "Read" });
  await expect(read).toBeDisabled();
  await expect(read).toHaveAttribute("title", /address is required/i);
  await expect(memory.getByText("Enter an address")).toBeVisible();

  await memory.getByRole("combobox", { name: "Kind", exact: true }).selectOption("file");
  await memory.getByLabel("Address", { exact: true }).fill("0");
  await memory.getByLabel("Length", { exact: true }).fill("16");
  await read.click();

  // Offset 0 of a PE is its DOS header, so the window starts with the MZ magic
  // and its gutter reads as text.  The grid is the only place those appear.
  const grid = memory.locator("table.data-table");
  await expect(grid.getByText("4d 5a", { exact: false })).toBeVisible();
  await expect(grid.getByText("MZ", { exact: false })).toBeVisible();
});

test("filtering the type list narrows it and counts stay exact", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelByTitle(page, "Data types");
  const total = state.types.length;

  await expect(types.getByText(`of ${total} types`, { exact: false })).toBeVisible();
  for (const name of state.types) {
    // A card's heading line carries the name plus its size and member count.
    await expect(types.getByText(name, { exact: false }).first()).toBeVisible();
  }

  await types.getByLabel("Filter", { exact: true }).fill(FILTER_TARGET);
  await expect(types.getByText(`1 of ${total} types`, { exact: false })).toBeVisible();

  await types.getByLabel("Filter", { exact: true }).fill("no-such-type-anywhere");
  await expect(types.getByText("No type matches", { exact: false })).toBeVisible();
});

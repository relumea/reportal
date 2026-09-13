// The Data types panel's filters: the kind select and the namespace tree both
// narrow the rendered rows through the API, and the counts report the slice.

import type { Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// Seeded names that make each filter's result set unambiguous.
const STRUCT_NAME = "NP_HEADER";
const ENUM_NAME = "NP_FLAGS";
const NAMESPACED_TYPEDEF = "WIN_DWORD";
const NAMESPACED_POINTER = "WIN_HANDLE";

function panelTypes(page: Page) {
  return panelByTitle(page, "Data types");
}

test("the kind filter narrows the type list", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();
  await types.getByRole("combobox", { name: "Kind filter", exact: true }).selectOption("enum");

  await expect(types.getByText(ENUM_NAME, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(STRUCT_NAME, { exact: false })).toHaveCount(0);
  await expect(types.getByText(`1 of ${state.types.length} types`, { exact: false })).toBeVisible();
});

test("the namespace tree filters by branch and collapses", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();
  await types.getByRole("button", { name: /^winnt / }).click();

  await expect(types.getByText(NAMESPACED_TYPEDEF, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(NAMESPACED_POINTER, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(STRUCT_NAME, { exact: false })).toHaveCount(0);
  await expect(types.getByText(`3 of ${state.types.length} types`, { exact: false })).toBeVisible();

  await expect(types.getByRole("button", { name: /^kernel / })).toBeVisible();
  await types.getByRole("button", { name: "Collapse", exact: true }).click();
  await expect(types.getByRole("button", { name: /^kernel / })).toHaveCount(0);
});

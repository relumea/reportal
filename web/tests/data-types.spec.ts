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
const FUNCTION_TYPE = "NP_CALLBACK";

function panelTypes(page: Page) {
  return panelByTitle(page, "Data types");
}

test("the kind filter narrows the type list", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();
  await expect(types.locator(".name-source-dot").first()).toBeVisible();
  const headerCard = types.locator(".card").filter({ hasText: /NP_HEADER struct/ }).first();
  await expect(headerCard.getByText(/Binary · \d+ bytes/)).toBeVisible();
  const typeLink = types.getByRole("link", { name: "NP_ENTRY" }).first();
  await expect(typeLink).toHaveAttribute("href", /search=NP_ENTRY/);
  await expect(types.getByText(/3 members · \d+ bytes/).first()).toBeVisible();
  const entryCard = types.locator(".card").filter({ hasText: /NP_ENTRY struct/ }).first();
  await entryCard.getByRole("button", { name: "References" }).click();
  await expect(entryCard.getByRole("heading", { name: "Referenced by" })).toBeVisible();
  await expect(
    entryCard.getByRole("link", { name: "NP_HEADER" }),
  ).toHaveAttribute("href", /search=NP_HEADER/);
  await expect(types.locator(".code-scroll").first()).toHaveAttribute("title", "Click to copy");
  await types.getByRole("button", { name: /^enum: / }).click();
  await expect(types.getByRole("button", { name: /^typedef: / })).toHaveAttribute(
    "title",
    "Type alias",
  );
  await expect(types.getByRole("button", { name: /^\*: / })).toHaveAttribute("title", "pointer *");
  await expect(types.getByRole("button", { name: /^\[\]: / })).toHaveAttribute("title", "array []");
  await expect(types.getByRole("button", { name: /^fn: / })).toHaveAttribute("title", "function ()");

  await expect(types.getByText(ENUM_NAME, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(STRUCT_NAME, { exact: false })).toHaveCount(0);
  await expect(types.getByText(`1 of ${state.types.length} types`, { exact: false })).toBeVisible();
  await types.getByRole("button", { name: "Clear all filters", exact: true }).click();
  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();
  await expect(types.getByRole("button", { name: /Clear/ })).toHaveCount(0);
});

test("a function type shows its return and parameters", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);
  await types.getByPlaceholder(/Search \d+ types or namespaces/).fill(FUNCTION_TYPE);
  const card = types.locator(".card").filter({ hasText: FUNCTION_TYPE }).first();
  await expect(card.getByText("Returns")).toBeVisible();
  await expect(card.getByRole("link", { name: NAMESPACED_TYPEDEF }).first()).toBeVisible();
  await expect(card.getByRole("columnheader", { name: "Parameter" })).toBeVisible();
  await expect(card.getByRole("columnheader", { name: "Offset" })).toHaveCount(0);
  await expect(card.getByLabel("Name of member entry")).toHaveValue("entry");
  await expect(card.getByLabel("Type of member entry")).toHaveValue("NP_ENTRY *");
  await expect(card.getByText("1 parameters")).toBeVisible();
});

test("the search matches a namespace", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);
  await types.getByPlaceholder(/Search \d+ types or namespaces/).fill("winnt");
  await expect(types.getByText(NAMESPACED_TYPEDEF, { exact: false }).first()).toBeVisible();
  await expect(types.getByText("Aliases").first()).toBeVisible();
  const handleCard = types.locator(".card").filter({ hasText: NAMESPACED_POINTER }).first();
  await expect(handleCard.getByTitle("pointer *")).toHaveText("*");
  await expect(handleCard.getByRole("link", { name: NAMESPACED_TYPEDEF }).first()).toBeVisible();
  await expect(handleCard.getByText(/Type alias · \d+ bytes/)).toBeVisible();
  await expect(types.getByText(STRUCT_NAME, { exact: false })).toHaveCount(0);
  await expect(types.getByRole("button", { name: /Clear/ })).toHaveCount(0);
});

test("the namespace tree filters by branch and collapses", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);

  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();
  await expect(types.getByPlaceholder("Search namespaces...")).toBeVisible();
  await types.getByRole("button", { name: /^winnt / }).click();

  await expect(types.getByText(NAMESPACED_TYPEDEF, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(NAMESPACED_POINTER, { exact: false }).first()).toBeVisible();
  await expect(types.getByText(STRUCT_NAME, { exact: false })).toHaveCount(0);
  await expect(types.getByText(`3 of ${state.types.length} types`, { exact: false })).toBeVisible();

  await expect(types.getByRole("button", { name: /^kernel / })).toHaveClass(/is-covered/);
  await types.getByRole("button", { name: "Collapse", exact: true }).click();
  await expect(types.getByRole("button", { name: /^kernel / })).toHaveCount(0);
});

test("the sort control orders the list the way the route ordered it", async ({ page }) => {
  // The seeded names, so the read-back order ignores every other badge the
  // panel renders (kind labels and the provenance strip's chips).
  const seeded = [STRUCT_NAME, ENUM_NAME, NAMESPACED_TYPEDEF, NAMESPACED_POINTER, "NP_ENTRY"];
  const cardOrder = (): Promise<string[]> =>
    panelTypes(page)
      .locator(".badge")
      .evaluateAll(
        (nodes, names) =>
          nodes
            .map((node) => (node.textContent ?? "").trim())
            .filter((text) => (names as string[]).includes(text)),
        seeded,
      );

  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);
  await expect(types.getByText(STRUCT_NAME, { exact: false }).first()).toBeVisible();

  await types.getByRole("combobox", { name: "Sort", exact: true }).selectOption("size");
  await types.getByRole("combobox", { name: "Direction", exact: true }).selectOption("desc");
  await expect(page).toHaveURL(/sort=size/);
  await expect(page).toHaveURL(/direction=desc/);

  // What the panel draws is the order the route applied, not the browser's.
  const response = await page.request.get(
    `/api/binaries/${state.ids.binary_id}/data-types?sort=size&direction=desc`,
  );
  const payload = (await response.json()) as { types: Array<{ name: string }> };
  const expected = payload.types
    .map((dataType) => dataType.name)
    .filter((name) => seeded.includes(name));
  await expect.poll(cardOrder).toEqual(expected);
  expect(expected.length).toBeGreaterThan(1);

  // The control survives a reload, which is what keeping it in the hash buys.
  await page.reload();
  await expect(types.getByRole("combobox", { name: "Sort", exact: true })).toHaveValue("size");
  await expect(types.getByRole("combobox", { name: "Direction", exact: true })).toHaveValue("desc");
});

// The Data types panel's editor: the member shape and position, the
// kind/namespace/declared-size write, explicit padding and the enum values.
// Each test drives the real controls against the seeded workspace.

import type { Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// Seeded types the editor tests drive.  NP_HEADER is a manual struct no other
// spec depends on; NP_FLAGS is the workspace's only enum; NP_BLOCK is a union
// whose shape the kind switch changes.
const STRUCT_NAME = "NP_HEADER";
const ENUM_NAME = "NP_FLAGS";
const UNION_NAME = "NP_BLOCK";

function panelTypes(page: Page) {
  return panelByTitle(page, "Data types");
}

function cardFor(page: Page, name: string) {
  return panelTypes(page).locator(".card").filter({ hasText: name }).first();
}

/** The member row that owns a control's aria-label. */
function memberRow(card: ReturnType<typeof cardFor>, member: string) {
  return card
    .getByLabel(`Bit width of member ${member}`, { exact: true })
    .locator("xpath=ancestor::tr");
}

/** The enum value row that owns a control's aria-label. */
function valueRow(card: ReturnType<typeof cardFor>, name: string) {
  return card
    .getByLabel(`Name of enum value ${name}`, { exact: true })
    .locator("xpath=ancestor::tr");
}

test("a member's bit width is set and cleared", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const card = cardFor(page, STRUCT_NAME);
  await expect(card).toBeVisible();

  const row = memberRow(card, "flags");
  await row.getByLabel("Bit width of member flags", { exact: true }).fill("5");
  await row.getByLabel("Bit width of member flags", { exact: true }).press("Escape");
  await expect(row.getByLabel("Bit width of member flags", { exact: true })).toHaveValue("");
  await row.getByLabel("Bit width of member flags", { exact: true }).fill("5");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect(card.getByText("flags : 5", { exact: false })).toBeVisible();

  await row.getByLabel("Bit width of member flags", { exact: true }).fill("");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect(card.getByText("flags : 5", { exact: false })).toHaveCount(0);
});

test("a member is inserted after another from the row action", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const card = cardFor(page, STRUCT_NAME);

  await card.getByLabel("Add member", { exact: true }).fill("afterMagic");
  await card.getByLabel("Type", { exact: true }).fill("char");
  const row = memberRow(card, "magic");
  await row.getByRole("button", { name: "Insert member after", exact: true }).click();

  await expect(card.getByText("char afterMagic;", { exact: false })).toBeVisible();
});

test("a member converts to a gap and back", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const card = cardFor(page, STRUCT_NAME);

  const row = memberRow(card, "magic");
  await row.getByRole("button", { name: "Convert to gap", exact: true }).click();
  await expect(card.getByText("char gap_0000[2];", { exact: false })).toBeVisible();

  const gapRow = memberRow(card, "gap_0000");
  await gapRow.getByLabel("Name of member gap_0000", { exact: true }).fill("header");
  await gapRow.getByLabel("Type of member gap_0000", { exact: true }).fill("unsigned short");
  await gapRow.getByRole("button", { name: "Convert to member", exact: true }).click();
  await expect(card.getByText("unsigned short header;", { exact: false })).toBeVisible();
});

test("an enum value is added, revalued and removed", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelTypes(page);
  const card = cardFor(page, ENUM_NAME);
  await expect(card).toBeVisible();

  await card.getByLabel("Add value", { exact: true }).fill("NP_FLAG_C");
  await card.getByRole("button", { name: "Add value", exact: true }).click();
  // The add's note lives on the panel, since the model refresh remounts the
  // card subtree and would drop card-local state.
  await expect(types.getByText("auto-incremented to 2", { exact: false })).toBeVisible();

  const entry = valueRow(card, "NP_FLAG_C");
  await entry.getByLabel("Value of enum value NP_FLAG_C", { exact: true }).fill("0x40");
  await entry.getByRole("button", { name: "Save", exact: true }).click();
  // Wait for the write's refresh, not just the row's local hex echo: the
  // refresh remounts the rows and would drop an open confirm.
  await expect(entry.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  await expect(card.getByText("0x40", { exact: false }).first()).toBeVisible();

  const removal = valueRow(card, "NP_FLAG_C");
  await removal.getByRole("button", { name: "Remove", exact: true }).click();
  const confirm = removal.getByRole("group", { name: "Remove?" });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(card.getByLabel("Name of enum value NP_FLAG_C", { exact: true })).toHaveCount(0);
});

test("the kind, namespace and declared size save together and warn", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const card = cardFor(page, UNION_NAME);
  await expect(card).toBeVisible();

  // A select's label text includes its options, so the control is named by role.
  await card.getByRole("combobox", { name: "Kind", exact: true }).selectOption("struct");
  await card.getByLabel("Namespace", { exact: true }).fill("e2e::editor");
  await card.getByLabel("Size", { exact: true }).fill("16");
  await card.getByRole("button", { name: "Save fields", exact: true }).click();

  await expect(card.getByText("e2e::editor", { exact: false })).toBeVisible();
  await expect(card.getByText("disagrees with the members", { exact: false })).toBeVisible();

  await card.getByRole("combobox", { name: "Kind", exact: true }).selectOption("union");
  await card.getByLabel("Namespace", { exact: true }).fill("");
  await card.getByLabel("Size", { exact: true }).fill("4");
  await card.getByLabel("Size", { exact: true }).focus();
  await page.keyboard.press("Control+Enter");
  await expect(card.getByText("disagrees with the members", { exact: false })).toHaveCount(0);
});

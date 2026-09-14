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

// The single document the seeder ingests (`smoke_spa.DOCUMENT_TITLE`), whose
// text carries "toolbar" and does not mention the seeded function's name.
const KNOWLEDGE_DOCUMENT_TITLE = "Smoke knowledge note";

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

test("the cross-references panel scans on demand and renders what the engine found", async ({
  page,
}) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  // Located by its control, not its heading: the title carries the count badge.
  const xrefs = page
    .locator(".panel")
    .filter({ has: page.getByRole("button", { name: "Load cross-references" }) });

  await xrefs.getByRole("button", { name: "Load cross-references" }).click();
  await expect(xrefs.getByRole("button", { name: "Reload cross-references" })).toBeVisible();
  // A live engine scan, so the panel settles on its table or its explicit
  // empty state, and the fixture's guard already fails the test on a refusal.
  await expect(xrefs.locator("table, .empty-state")).toBeVisible();
  await expect(xrefs.getByRole("alert")).toHaveCount(0);
});

test("the scans panel lists the stored scans and the inputs they ran with", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  // Located by its heading shape, not `panelByTitle`: the badge is part of the name.
  const scans = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Scans \d+$/ }) });

  await expect(scans.getByText("filetype", { exact: true })).toBeVisible();
  await expect(scans.getByText("pe-info", { exact: true })).toBeVisible();
  // The security scan is the seeded one that recorded the floor it ran with.
  await expect(scans.getByText("min_severity=low", { exact: false })).toBeVisible();
});

test("a run a dead process left running can be recovered from the auto view", async ({ page }) => {
  await page.goto(`/#/auto/${state.stale_run.binary_id}`);
  // Located by its back link: the panel title names the binary, and the
  // recovery control itself is gone once the run is closed.
  const auto = page.locator(".panel").filter({ has: page.locator('a[href="#/auto"]') });

  // The confirm control of a ConfirmButton carries the same label.
  await auto.getByRole("button", { name: "Recover run" }).click();
  await auto.getByRole("button", { name: "Recover run" }).click();

  // The run is closed with its recorded writes kept revertible, so the control
  // it was offered through is gone.
  await expect(auto.getByText(/Closed run #\d+ as \w+: 1 task\(s\) interrupted/)).toBeVisible();
  await expect(auto.getByRole("button", { name: "Recover run" })).toHaveCount(0);
});

test("the function knowledge panel retrieves the binary's documents", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const knowledge = panelByTitle(page, "Knowledge");

  // A blank search asks about the function's own name, which the seeded note
  // never mentions, so the explicit empty state is the honest first answer.
  await knowledge.getByRole("button", { name: "Search documents" }).click();
  await expect(knowledge.getByText(/0 chunk\(s\) for/)).toBeVisible();
  await expect(knowledge.getByText("No matches", { exact: false })).toBeVisible();

  // A term the seeded note carries returns its chunk, ranked.
  await knowledge.getByLabel("Query", { exact: true }).fill("toolbar");
  await knowledge.getByRole("button", { name: "Search documents" }).click();
  await expect(knowledge.getByText(KNOWLEDGE_DOCUMENT_TITLE)).toBeVisible();
  await expect(knowledge.getByText(/1 chunk\(s\) for "toolbar"/)).toBeVisible();
});

test("each stored remediation artifact links to its raw read", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const remediation = panelByTitle(page, "Remediation");
  const base = `/api/binaries/${state.ids.binary_id}/remediation`;

  // The seeded scan carries all three artifacts, so each summary links to the
  // format route that serves that one.
  for (const format of ["yara", "snort", "stix"]) {
    await expect(remediation.locator(`a[href="${base}/${format}"]`)).toBeVisible();
  }
});

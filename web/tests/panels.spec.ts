// The panels added for the hosted portal's Memory and Data types surfaces:
// a real byte window read on demand, and the stored type list's filter.
// Both assert the rendered state, not just that the panel exists.

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining } from "./helpers";
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
  await expect(memory.getByLabel("Address", { exact: true })).toHaveAttribute(
    "placeholder",
    /^0x[0-9a-f]+$/i,
  );
  await expect(read).toHaveAttribute("title", /address is required/i);
  await expect(memory.getByText("Enter an address")).toBeVisible();

  await memory.getByRole("combobox", { name: "Kind", exact: true }).selectOption("file");
  await memory.getByLabel("Address", { exact: true }).fill("0");
  await memory.getByLabel("Length", { exact: true }).fill("16");
  await memory.getByLabel("Address", { exact: true }).press("Enter");

  // Offset 0 of a PE is its DOS header, so the window starts with the MZ magic
  // and its gutter reads as text.  The grid is the only place those appear.
  const grid = memory.locator("table.data-table");
  await expect(grid.getByRole("columnheader", { name: "Offset" })).toBeVisible();
  await expect(grid.getByRole("columnheader", { name: "Virtual" })).toBeVisible();
  await expect(grid.getByText("4d 5a", { exact: false })).toBeVisible();
  await expect(grid.getByText("MZ", { exact: false })).toBeVisible();
  await expect(grid.locator(".byte-zero").first()).toBeVisible();
  await memory.getByLabel("Address", { exact: true }).press("Escape");
  await expect(memory.getByLabel("Address", { exact: true })).toHaveValue("");
});

test("filtering the type list narrows it and counts stay exact", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const types = panelByTitle(page, "Data Types");
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

test("the binary header name is click-to-rename", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  await expect(page.getByRole("link", { name: "Download", exact: true })).toHaveAttribute(
    "href",
    `/api/binaries/${state.ids.binary_id}/download`,
  );
  await expect(page.getByRole("link", { name: "PDF", exact: true })).toHaveAttribute(
    "href",
    `/api/binaries/${state.ids.binary_id}/report/pdf`,
  );
  await expect(page.getByRole("link", { name: "Symbols", exact: true })).toHaveAttribute(
    "href",
    `/api/binaries/${state.ids.binary_id}/symbols/export`,
  );
  await expect(page.getByLabel("scope of notepad.exe")).toHaveValue("public");
  await expect(page.locator(".detail-facts").first()).toContainText(/\d{2}:\d{2}/);
  await expect(page.locator(".detail-facts").first()).toContainText(/PE/);
  await expect(page.locator(".detail-facts").first()).toContainText(/x86_32/);
  await page.getByRole("button", { name: "Tags", exact: true }).click();
  await expect(page.locator("#content section.panel:focus")).toContainText("Tags");
  const nameButton = page.getByRole("button", { name: "notepad.exe", exact: true });
  await nameButton.click();
  const input = page.getByLabel("Binary name");
  await expect(input).toHaveValue("notepad.exe");
  await input.fill("should-not-stick");
  await input.press("Escape");
  await expect(page.getByRole("button", { name: "notepad.exe", exact: true })).toBeVisible();
});

test("the binary header asserts format and ISA with provenance", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const facts = page.locator(".detail-facts").first();
  await expect(facts).toContainText(/PE/);

  // Hosted headers tell detection apart from a human assertion: asserting the
  // format marks the badge as hand-set, clearing it restores detection.
  const head = page.locator(".detail-head");
  await head.getByLabel("Assert the binary format").selectOption("elf");
  await head.getByRole("button", { name: "Save", exact: true }).click();
  const format = facts.getByTitle("Format asserted by hand");
  await expect(format).toHaveText("elf");
  await head.getByLabel("Assert the binary format").selectOption("");
  await head.getByRole("button", { name: "Save", exact: true }).click();
  await expect(facts.getByTitle("Detected format")).toHaveText(/PE/);
});

test("the function header name is click-to-rename", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const nameButton = page.getByRole("button", { name: state.function_name, exact: true });
  await nameButton.click();
  const input = page.getByLabel("Function name");
  await expect(input).toHaveValue(state.function_name);
  await input.fill("should-not-stick");
  await input.press("Escape");
  await expect(
    page.getByRole("button", { name: state.function_name, exact: true }),
  ).toBeVisible();
});

test("the function header signature shows its breakdown", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  await expect(page.locator(".sig-hover")).toContainText("smokeArg");
  await expect(page.locator(".sig-hover").getByRole("link", { name: "WIN_DWORD" })).toHaveAttribute(
    "href",
    /search=WIN_DWORD/,
  );
});

test("function matches opens the matching view", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const matches = panelByTitle(page, "Matches");
  await expect(matches.getByRole("columnheader", { name: "Signature" })).toBeVisible();
  const link = matches.getByRole("link", { name: "View function matching" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute(
    "href",
    `#/matches?function=${state.ids.function_id}`,
  );
  await link.click();
  await expect(page).toHaveURL(`/#/matches?function=${state.ids.function_id}`);
  await expect(page.getByText(/\d+ candidates? recorded/)).toBeVisible();
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

test("function globals link Memory and the function list", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const globals = page
    .locator(".panel")
    .filter({ has: page.getByRole("button", { name: "Load references" }) })
    .first();
  await globals.getByRole("button", { name: "Load references" }).click();
  const table = globals.locator("table.data-table");
  await expect(table.or(globals.locator(".empty-state"))).toBeVisible();
  if ((await table.count()) === 0) return;
  await expect(table.locator("a[href*='memory=']").first()).toBeVisible();
  await expect(table.locator(".copy-row").first()).toBeVisible();
  await expect(table.getByRole("link", { name: "Filter functions" }).first()).toBeVisible();
});

test("function callers names link a function", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const callers = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Callers / }) });
  await callers.getByRole("button", { name: "Load references" }).click();
  const table = callers.locator("table.data-table");
  await expect(table.or(callers.locator(".empty-state"))).toBeVisible();
  if ((await table.count()) === 0) return;
  await expect(table.locator("a[href^='#/functions/']").first()).toBeVisible();
});

test("composition analysis opens the matching view", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const composition = panelByTitle(page, "Composition Analysis");
  const link = composition.getByRole("link", { name: "Open Matching View" });
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", /#\/matches\?function=\d+/);
  const topBinary = composition.locator("table.data-table a[href^='#/binaries/']").first();
  await expect(topBinary).toBeVisible();
  await expect(composition.getByRole("heading", { name: "Function Name Sources" })).toBeVisible();
  await expect(composition.getByRole("heading", { name: "Match Quality" })).toBeVisible();
  await expect(composition.getByRole("heading", { name: "Categories" })).toBeVisible();
  const scopeMatch = composition.getByRole("link", { name: "Scope matching" });
  await expect(scopeMatch.first()).toHaveAttribute(
    "href",
    /#\/matches\?function=\d+&binary_ids=\d+/,
  );
  await expect(scopeMatch).not.toHaveCount(0);
  const sourceFilter = composition.locator("a.meter-link[href*='name_source=']").first();
  await expect(sourceFilter).toBeVisible();
  const quality = composition.locator("button.meter-link").first();
  await quality.click();
  await expect(quality).toHaveAttribute("data-selected", "true");
  const tagLink = composition.locator("a[href^='#/binaries?tag=']").first();
  await expect(tagLink).toBeVisible();
  await expect(sourceFilter).toHaveAttribute(
    "href",
    new RegExp(`#/binaries/${state.ids.binary_id}/functions\\?name_source=`),
  );
  await link.click();
  await expect(page).toHaveURL(/#\/matches\?function=/);
  await expect(page.getByText(/\d+ candidates? recorded/)).toBeVisible();
});

test("the binary details entry point links to a function", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const details = panelByTitle(page, "Binary Details");
  const link = details.getByTitle("Open the function at this address");
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("href", /#\/(functions\/\d+|binaries\/\d+\/functions\?va=)/);
  await expect(page.getByRole("heading", { name: /^Sections \d+$/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: /^Security \d+\/\d+$/ })).toBeVisible();
  const capabilities = page.locator(".panel").filter({
    has: page.getByRole("heading", { name: /^Capabilities/ }),
  });
  await capabilities.scrollIntoViewIfNeeded();
  const runResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/capabilities") &&
      response.request().method() === "POST" &&
      response.ok(),
  );
  await capabilities.getByRole("button", { name: "Run capability scan" }).click();
  const run = (await (await runResponse).json()) as { journal_action?: string };
  await expect(capabilities.getByRole("heading", { name: /^Capabilities \d+$/ })).toBeVisible({
    timeout: 60_000,
  });

  // The suite shares one seeded workspace, so undo the run through its own
  // journal entry and leave no stored scan behind for later specs.
  expect(run.journal_action).toBeTruthy();
  const revert = await page.request.post("/api/journal/revert", {
    data: { action: run.journal_action },
  });
  expect(revert.ok()).toBeTruthy();
  await expect(page.getByRole("heading", { name: /^Relocations \d+$/ })).toBeVisible();
  const imports = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Imports / }) });
  await imports.locator("button.panel-fold").click();
  await imports.getByRole("button", { name: "Load imports" }).click();
  const importLink = imports.locator("table.data-table a[href*='functions?name=']").first();
  await expect(importLink).toBeVisible({ timeout: 60_000 });
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

test("the binary's collections panel reads and changes its membership", async ({ page }) => {
  const collection = state.collections[0].name;
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  // The title carries the count badge, so the panel is located by its shape.
  const collections = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Collections \d+$/ }) });

  // The seeder puts the binary in one collection, from the collection's side.
  await expect(collections.getByRole("cell", { name: collection })).toBeVisible();

  // The same panel removes it, and the confirm control carries the same label.
  await collections.getByRole("button", { name: "Remove" }).click();
  await collections.getByRole("button", { name: "Remove" }).click();
  await expect(collections.getByText("This binary is in no collection.")).toBeVisible();

  // And puts it back, so the workspace is as this spec found it.
  await collections.getByRole("combobox").selectOption({ label: collection });
  await collections.getByRole("button", { name: "Add" }).click();
  await expect(collections.getByRole("cell", { name: collection })).toBeVisible();
});

test("the external view names the analysis's own status before a pull", async ({ page }) => {
  await page.goto("/#/external");
  const pull = panelByTitle(page, "Pull a report");

  // The status read needs an analysis, so it says so until one is named.
  await expect(pull.getByText(/Name an analysis to see whether/)).toBeVisible();

  await pull.getByLabel("Analysis", { exact: true }).fill(String(state.ids.analysis_id));
  // The offline source never leaves the machine and answers from stored rows,
  // and the seed stores no external answer, so the first status says so.
  await expect(pull.getByText(/available, nothing stored for this source yet/)).toBeVisible();

  await pull.getByRole("button", { name: "Pull", exact: true }).click();
  await expect(pull.getByText(/stored, fetched/)).toBeVisible();
  // The hourly cooldown gates remote re-pulls only: the offline pull stays
  // enabled right after fetching.
  await expect(pull.getByRole("button", { name: "Pull", exact: true })).toBeEnabled();
});

test("the binary header names the analysis context its engine reads use", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);

  // The seeder imports a project, and every engine-backed panel on this page
  // (disassembly, cross-references, structs) reads through it.
  await expect(page.getByText("analysis context ready", { exact: true })).toBeVisible();
});

test("the AI summary panel discards the artifact it shows", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const summary = panelByTitle(page, "Summary");

  // The seeder stores one, so the panel renders its payload rather than the
  // nothing-stored hint, and offers the discard.
  await expect(summary.getByText(/Reads the configuration file/)).toBeVisible();

  // The confirm control of a ConfirmButton carries the same label.
  await summary.getByRole("button", { name: "Discard", exact: true }).click();
  await summary.getByRole("button", { name: "Discard", exact: true }).click();

  await expect(summary.getByText("No AI summary stored for this function")).toBeVisible();
});

test("a binary's detail lists only that binary's analyses", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const analyses = panelByTitle(page, "Analyses");

  // The counts are the binary-scoped ones, so a panel that ignored the filter
  // and listed the workspace's analyses would disagree with this read.
  const scoped = await page.request.get(`/api/analyses?binary_id=${state.ids.binary_id}`);
  const payload = (await scoped.json()) as { count: number; total: number };
  await expect(
    analyses.getByText(`${payload.count} of ${payload.total} analyses`),
  ).toBeVisible();
  await expect(rowContaining(analyses, String(state.ids.analysis_id))).toBeVisible();
  await expect(analyses.getByRole("link", { name: "All analyses" })).toBeVisible();
});

test("the auto run form sends every run knob the route takes", async ({ page }) => {
  await page.goto(`/#/auto/${state.ids.binary_id}`);
  const auto = page.locator(".panel").filter({ has: page.locator('a[href="#/auto"]') });

  // The knobs the form did not carry, each filled to a value no default
  // would produce.  The run itself is not started: the answer is written here,
  // because the pool would plan real batches behind the rest of the suite.
  await auto.getByLabel("Functions per task").fill("2");
  await auto.getByLabel("Max attempts").fill("3");
  await auto.getByLabel("Max tasks").fill("50");
  await auto.getByLabel("Max tokens").fill("1000");
  await auto.locator("#auto-max-usd").fill("0.25");
  await auto.getByLabel("USD per million tokens").fill("1.5");
  await page.route("**/api/binaries/*/auto", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        run_id: 999,
        binary_id: state.ids.binary_id,
        status: "running",
      }),
    });
  });

  const sent = page.waitForRequest(
    (request) => request.method() === "POST" && request.url().endsWith("/auto"),
  );
  await auto.getByRole("button", { name: "Start run" }).click();

  expect((await sent).postDataJSON()).toMatchObject({
    functions_per_task: 2,
    max_attempts: 3,
    max_tasks: 50,
    max_tokens: 1000,
    max_usd: 0.25,
    usd_per_mtok: 1.5,
  });
  await expect(auto.getByText(/Started auto run #999/)).toBeVisible();
});

test("a gated scan panel carves without a prior fetch", async ({ page }) => {
  // Firmware is one scan the seeder never stores, so the panel gates its GET
  // off and renders the empty state with no request: the carve below is the
  // first firmware traffic for this binary.
  const firmwareGets: string[] = [];
  await page.route("**/api/binaries/*/firmware", async (route) => {
    if (route.request().method() === "GET") firmwareGets.push(route.request().url());
    return route.continue();
  });
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const firmware = panelByTitle(page, "Firmware carving");
  await expect(firmware.getByText(/No firmware carve yet/)).toBeVisible();
  expect(firmwareGets).toEqual([]);

  // The Run control loads the gated panel through the same refresh path an
  // ungated panel uses: the carve stores the scan and the panel renders it,
  // all without a single GET (the POST's own payload populates the entry).
  await firmware.getByRole("button", { name: "Carve" }).click();
  await expect(firmware.getByText(/region\(s\) in \d+ bytes/)).toBeVisible();
  expect(firmwareGets).toEqual([]);
});

test("an artifact note round-trips through the panel", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const feedback = panelByTitle(page, "Agent Feedback");
  const row = feedback.locator("table.table tbody tr").first();

  // The seeded scans carry no notes, so the row starts clean and the note
  // control is hidden until asked for.
  await expect(row.getByText("unrated")).toBeVisible();
  await expect(row.getByRole("button", { name: "Note", exact: true })).toBeVisible();

  await row.getByRole("button", { name: "Note", exact: true }).click();
  const noteField = feedback.getByLabel(/Note for /);
  await noteField.fill("worth a second look");
  await feedback.getByRole("button", { name: "Save note", exact: true }).click();

  // The same verdict line now carries the stored text, not just the badge.
  await expect(row.getByText("worth a second look")).toBeVisible();

  // And the read behind the table reports it, so the assertion is the stored
  // row rather than the row's own render.
  const saved = await page.request.get(`/api/binaries/${state.ids.binary_id}/ratings`);
  const payload = (await saved.json()) as {
    artifacts: Array<{ rating: { rating: string; note: string } | null }>;
  };
  const noted = payload.artifacts.filter((entry) => entry.rating?.note === "worth a second look");
  expect(noted.length).toBe(1);
  expect(noted[0].rating?.rating).toBe("up");

  // Clear the verdict so the seeded workspace reads unrated again for later
  // specs: the clear path is the same one the table's Clear button uses.
  await row.getByRole("button", { name: "Note", exact: true }).click();
  await feedback.getByLabel(/Note for /).fill("x");
  await feedback.getByRole("button", { name: "Save note", exact: true }).click();
  await row.getByRole("button", { name: "Clear", exact: true }).click();
  await expect(row.getByText("unrated")).toBeVisible();
});

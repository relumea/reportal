// Usability fixes across the workbench: header downloads that never link to a
// refusal, the rename-script menu, AI controls gated on a configured model,
// reachable journal actions, inline renames, address search, the upload entry
// point and detail routes for rows that do not exist.

import { e2eState } from "./e2e-state";
import { expect, test } from "./fixtures";
import { panelByTitle, rowContaining, uniqueName } from "./helpers";

const state = e2eState();

const NO_MODEL = "No model is configured for this workspace.";

test("the binary header generates a missing PDF and explains a missing symbol file", async ({
  page,
}) => {
  const id = state.ids.binary_id;
  const status = (await (await page.request.get(`/api/binaries/${id}/report/pdf/status`)).json()) as {
    exists: boolean;
  };
  expect(status.exists).toBe(false);

  await page.goto(`/#/binaries/${id}`);
  const symbols = page.getByRole("button", { name: "Symbols", exact: true });
  await expect(symbols).toBeDisabled();
  await expect(symbols).toHaveAttribute("title", /No debug symbol file is ingested/);

  await page.getByRole("button", { name: "Generate PDF", exact: true }).click();
  const pdf = page.getByRole("link", { name: "PDF", exact: true });
  await expect(pdf).toHaveAttribute("href", `/api/binaries/${id}/report/pdf`);
  const served = await page.request.get(`/api/binaries/${id}/report/pdf`);
  expect(served.status()).toBe(200);
  expect(served.headers()["content-type"]).toBe("application/pdf");
});

test("Export renames downloads each decompiler's script as a named file", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  await page.getByText("Export renames", { exact: true }).click();
  for (const [label, filename] of [
    ["Ghidra script", "notepad_renames_ghidra.py"],
    ["IDA script", "notepad_renames_ida.py"],
    ["Binary Ninja JSON", "notepad_renames_binja.json"],
  ] as const) {
    const item = page.getByRole("link", { name: label, exact: true });
    if (!(await item.isVisible())) await page.getByText("Export renames", { exact: true }).click();
    const download = page.waitForEvent("download");
    await item.click();
    expect((await download).suggestedFilename()).toBe(filename);
  }
});

test("AI controls say no model is configured instead of failing on click", async ({ page }) => {
  const models = (await (await page.request.get("/api/models")).json()) as {
    models: Array<{ kind: string; available: boolean }>;
  };
  expect(models.models.some((entry) => entry.kind === "llm" && entry.available)).toBe(false);

  await page.goto(`/#/conversations/${state.ids.conversation_id}`);
  await expect(page.getByText(NO_MODEL)).toBeVisible();
  await expect(page.getByRole("link", { name: "Open Models" })).toHaveAttribute("href", "#/models");
  await page.getByLabel("Message", { exact: true }).fill("What does this do?");
  const send = page.getByRole("button", { name: "Send", exact: true });
  await expect(send).toBeDisabled();
  await expect(send).toHaveAttribute("title", NO_MODEL);
  await page.getByLabel("Agent question", { exact: true }).fill("Name the entry point.");
  await expect(page.getByRole("button", { name: "Run agent", exact: true })).toBeDisabled();
  await expect(page.getByText(/REPORTAL_LLM/)).toHaveCount(0);

  await page.goto(`/#/functions/${state.ids.function_id}?tab=ai`);
  await expect(page.getByText(NO_MODEL)).toHaveCount(1);
  for (const name of ["Generate", "Suggest", "Rewrite"]) {
    const buttons = page.getByRole("button", { name, exact: true });
    await expect(buttons.first()).toBeVisible();
    for (const button of await buttons.all()) {
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute("title", NO_MODEL);
    }
  }
  // The pipeline runs its non-model steps without one, so it stays available.
  await expect(page.getByRole("button", { name: /^(Run pipeline|Re-run)$/ })).toBeEnabled();
});

test("journal revert actions stay in view at a laptop width and lock once reverted", async ({
  page,
}) => {
  const name = uniqueName("e2e-journal-width");
  // An upload journals its stored path, an unbroken string wider than the table.
  const uploaded = await page.request.post("/api/binaries", {
    multipart: {
      file: { name: `${name}.bin`, mimeType: "application/octet-stream", buffer: Buffer.from(name) },
    },
  });
  expect(uploaded.ok()).toBe(true);
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=review`);
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(rowContaining(tags, name)).toBeVisible();
  const action = ((await tags.locator('a[href^="#/journal/"]').textContent()) ?? "").trim();
  expect(action).not.toBe("");

  await page.setViewportSize({ width: 1024, height: 800 });
  await page.goto("/#/journal");
  const panel = panelByTitle(page, "Journal");
  const row = rowContaining(panel, action).first();
  const scroller = panel.locator(".table-scroll").first();
  const edge = await scroller.boundingBox();
  expect(edge).not.toBeNull();
  for (const label of ["Revert entry", "Revert action"]) {
    const box = await row.getByRole("button", { name: label, exact: true }).boundingBox();
    expect(box).not.toBeNull();
    expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual((edge?.x ?? 0) + (edge?.width ?? 0));
  }

  await row.getByRole("button", { name: "Revert action", exact: true }).click();
  await row.getByRole("button", { name: "Revert action", exact: true }).click();
  await expect(page.getByText(/reverted \d+/)).toBeVisible();
  await expect(row.getByRole("button", { name: "Revert entry", exact: true })).toBeDisabled();
  await expect(row.getByRole("button", { name: "Revert action", exact: true })).toBeDisabled();
});

test("clicking a function's name opens a focused editor with the name selected", async ({
  page,
}) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const title = page.locator(".detail-title-name");
  await expect(title.locator(".icon")).toBeVisible();
  const shown = (await title.innerText()).trim();
  await title.click();
  const editor = page.getByRole("textbox", { name: "Function name" });
  await expect(editor).toBeFocused();
  const selection = await editor.evaluate((input: HTMLInputElement) => [
    input.selectionStart,
    input.selectionEnd,
    input.value.length,
  ]);
  expect(selection).toEqual([0, shown.length, shown.length]);
  await editor.press("Escape");
  await expect(page.locator(".detail-title-name")).toHaveText(shown);
});

test("the top bar Search opens the modal and a bare hex VA finds the function", async ({
  page,
}) => {
  const fn = (await (await page.request.get(`/api/functions/${state.ids.function_id}`)).json()) as {
    va: number;
  };
  await page.goto("/#/binaries");
  const trigger = page.locator(".topbar").getByRole("button", { name: /^Search/ });
  await expect(trigger).toContainText(/Ctrl\+K|⌘K/);
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Global search" });
  await expect(dialog).toBeVisible();
  await page.keyboard.type(fn.va.toString(16));
  const hit = dialog.locator('[data-hit-kind="function"]').filter({ hasText: "notepad.exe" }).first();
  await expect(hit).toBeVisible();
  await expect(hit).toContainText("matched va");
  await expect(hit).toContainText(`0x${fn.va.toString(16)}`);
});

test("the dashboard offers an upload even when binaries exist", async ({ page }) => {
  await page.goto("/#/");
  const upload = panelByTitle(page, "Jump to").getByRole("link", { name: "Upload binaries" });
  await expect(upload).toHaveAttribute("href", "#/binaries");
  await upload.click();
  await expect(panelByTitle(page, "Upload binaries")).toBeVisible();
});

test.describe("a detail route for a missing row", () => {
  test.use({
    expectedMissing: ["binary not found", "function not found", "conversation not found"],
  });

  for (const [path, title, list, back] of [
    ["/#/binaries/999999", "Binary not found", "Back to binaries", /#\/binaries$/],
    ["/#/functions/999999", "Function not found", "Back to functions", /#\/functions$/],
    ["/#/conversations/999999", "Conversation not found", "Back to conversations", /#\/conversations$/],
  ] as const) {
    test(`${path} says ${title} and links back`, async ({ page }) => {
      await page.goto(path);
      await expect(page.locator("#title")).toHaveText(title);
      await expect(page).toHaveTitle(`${title} · relumea`);
      await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
      await page.getByRole("link", { name: list, exact: true }).click();
      await expect(page).toHaveURL(back);
    });
  }
});

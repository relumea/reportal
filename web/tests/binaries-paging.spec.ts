// The register is read a page at a time: the first page is the table, and Load
// more appends the next one until every row the filter kept is loaded.  The
// route is answered here rather than by a seeded workspace, so the page size
// and the register size are exact and the assertion holds on any workspace.

import { expect, test } from "./fixtures";
import { panelByTitle } from "./helpers";
import type { Page } from "@playwright/test";

const PAGE_SIZE = 200;
const REGISTER = 250;

function row(id: number): Record<string, unknown> {
  return {
    id,
    sha256: id.toString(16).padStart(64, "0"),
    name: `sample-${id}.exe`,
    path: `/samples/sample-${id}.exe`,
    size: 4096 + id,
    format: "PE",
    arch: "x86_64",
    language: "",
    compiler: "",
    notes: "",
    function_count: 0,
    comment_count: 0,
    visibility: "public",
    owner_team_id: null,
  };
}

/** Answer the register route from memory: a page per `limit`/`offset` request. */
async function serveRegister(page: Page): Promise<void> {
  await page.route("**/api/binaries?*", async (route) => {
    const url = new URL(route.request().url());
    const params = url.searchParams;
    if (params.get("summary") === "true") {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          binaries: Array.from({ length: REGISTER }, (_value, index) => ({
            id: index + 1,
            name: `sample-${index + 1}.exe`,
          })),
          count: REGISTER,
          matched: REGISTER,
          total: REGISTER,
          limit: null,
          offset: 0,
          summary: true,
        }),
      });
    }
    const limit = Number(params.get("limit") ?? REGISTER);
    const offset = Number(params.get("offset") ?? 0);
    const binaries = Array.from({ length: REGISTER }, (_value, index) => row(index + 1)).slice(
      offset,
      offset + limit,
    );
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        binaries,
        count: binaries.length,
        matched: REGISTER,
        total: REGISTER,
        limit,
        offset,
        search: null,
        tag: null,
        format: null,
        language: null,
        compiler: null,
        order: "id",
        summary: false,
        formats: ["PE"],
        languages: [],
        compilers: [],
      }),
    });
  });
}

test("the register loads its first page and appends the next on demand", async ({ page }) => {
  await serveRegister(page);
  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Binaries");

  // The first page is what the route asked for, and the subtitle counts it
  // against the rows the filter kept rather than against what was fetched.
  await expect(panel.getByText(`${PAGE_SIZE} of ${REGISTER} binaries`)).toBeVisible();
  const loadMore = panel.getByRole("button", { name: "Load more" });
  await expect(loadMore).toBeVisible();
  await expect(panel.getByText(`${PAGE_SIZE} of ${REGISTER} loaded`)).toBeVisible();

  // Load more appends the remaining rows and then goes away, because every row
  // the filter kept is loaded.
  await loadMore.click();
  await expect(panel.getByText(`${REGISTER} of ${REGISTER} binaries`)).toBeVisible();
  await expect(panel.getByRole("button", { name: "Load more" })).toHaveCount(0);
});

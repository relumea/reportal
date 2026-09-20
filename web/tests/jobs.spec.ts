// The Jobs view's filters: the status, kind, binary and show controls narrow
// the queue through the API and live in the route hash, so a filtered queue is
// a link.  One composition job is queued through the view's own form (the kind
// stores a scan with no engine call), and its status is read from the API
// rather than assumed, so the assertions do not depend on how fast the pool is.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();
const TERMINAL = ["done", "failed", "cancelled"];

test("a queued job is listed and the filters narrow the queue", async ({ page }) => {
  await page.goto("/#/jobs");
  const panel = panelByTitle(page, "Jobs");
  const rows = panel.locator("table.data-table tbody tr");
  const binaryJobs = `/api/jobs?binary_id=${state.ids.binary_id}`;

  // Queue one job through the form the view carries.
  await panel.getByRole("combobox", { name: "Operation", exact: true }).selectOption("composition");
  await panel
    .getByRole("textbox", { name: "Binary", exact: true })
    .fill(String(state.ids.binary_id));
  await panel.getByRole("button", { name: "Queue job", exact: true }).click();

  // The binary filter narrows the queue to that job, and the view polls until
  // it is terminal, so the status it carries is read rather than assumed.
  const binaryFilter = panel.getByRole("textbox", { name: "Binary filter" });
  await binaryFilter.fill(String(state.ids.binary_id));
  await binaryFilter.press("Enter");
  await expect(page).toHaveURL(new RegExp(`binary_id=${state.ids.binary_id}`));
  await expect(rows.first()).toBeVisible();
  await expect
    .poll(async () => {
      const payload = (await (await page.request.get(binaryJobs)).json()) as {
        jobs: Array<{ status: string }>;
      };
      return (
        payload.jobs.length > 0 &&
        payload.jobs.every((job) => TERMINAL.includes(job.status))
      );
    })
    .toBe(true);
  const listed = (await (await page.request.get(binaryJobs)).json()) as {
    jobs: Array<{ status: string }>;
  };
  await expect(rows).toHaveCount(listed.jobs.length);
  // One status keeps the job, another empties the list without emptying the
  // queue: the count line reports the filtered and the matched total.
  const status = listed.jobs[0].status;
  const other = ["queued", "running", "done", "failed", "cancelled"].find(
    (value) => value !== status,
  );
  await panel.getByRole("combobox", { name: "Status filter", exact: true }).selectOption(status);
  await expect(rows.first()).toBeVisible();
  await panel
    .getByRole("combobox", { name: "Status filter", exact: true })
    .selectOption(String(other));
  await expect(rows).toHaveCount(0);
  await expect(panel.getByText("0 shown of 0")).toBeVisible();

  // Clear filters puts the whole queue back, and the Show control is a filter too.
  await panel.getByRole("button", { name: "Clear filters" }).click();
  await expect(page).toHaveURL(/#\/jobs$/);
  await panel.getByRole("spinbutton", { name: "Show" }).fill("5");
  await expect(page).toHaveURL(/limit=5/);
});

test("the queue form offers the match settings the kind takes", async ({ page }) => {
  await page.goto("/#/jobs");
  const panel = panelByTitle(page, "Jobs");

  // The floor is a match setting, so it is offered only for that kind; the
  // spec does not queue the run, because the pool would pick it up and score
  // the whole corpus behind the rest of the suite.
  await expect(panel.getByRole("textbox", { name: "Similarity floor" })).toHaveCount(0);

  await panel.getByRole("combobox", { name: "Operation", exact: true }).selectOption("match");

  await expect(panel.getByRole("textbox", { name: "Similarity floor" })).toBeVisible();
  // A match run still needs the binary it matches.
  await expect(panel.getByRole("button", { name: "Queue job", exact: true })).toBeDisabled();
});

test("a running job keeps the table polling until it finishes", async ({ page }) => {
  // Queue one composition job and let the pool finish it, so the API's own
  // answer is terminal and the assertion has a fixed target.
  const queued = await page.request.post("/api/jobs", {
    data: { kind: "composition", binary_id: state.ids.binary_id },
  });
  const job = (await queued.json()) as { id: number };
  await expect
    .poll(async () => {
      const one = await page.request.get(`/api/jobs/${job.id}`);
      return ((await one.json()) as { status: string }).status;
    })
    .not.toBe("queued");

  // The first list read is answered as if the job were still running with an
  // empty waiting queue, which is the state a poll keyed on that count stops
  // at.  Only a poll that follows the live row reaches the real status.
  let firstRead = true;
  await page.route(
    (url) => url.pathname === "/api/jobs",
    async (route) => {
      if (!firstRead) return route.continue();
      firstRead = false;
      const response = await route.fetch();
      const payload = (await response.json()) as {
        jobs: Array<Record<string, unknown>>;
      };
      payload.jobs = payload.jobs.map((row) =>
        row.id === job.id ? { ...row, status: "running", live: true } : row,
      );
      await route.fulfill({ response, json: payload });
    },
  );
  await page.goto("/#/jobs");
  const rows = panelByTitle(page, "Jobs").locator("table.data-table tbody tr");
  const row = rows.filter({
    has: page.getByRole("cell", { name: String(job.id), exact: true }),
  });
  await expect(row.getByRole("cell").nth(3)).toHaveText("running");
  await expect(row.getByRole("cell").nth(3)).toHaveText("done");
});

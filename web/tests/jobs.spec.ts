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
  await panel.getByRole("button", { name: "Queue", exact: true }).click();

  // The binary filter narrows the queue to that job, and the view polls until
  // it is terminal, so the status it carries is read rather than assumed.
  await panel.getByRole("textbox", { name: "Binary filter" }).fill(String(state.ids.binary_id));
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

  // Clear puts the whole queue back, and the Show control is a filter too.
  await panel.getByRole("button", { name: "Clear" }).click();
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
  await expect(panel.getByRole("button", { name: "Queue", exact: true })).toBeDisabled();
});

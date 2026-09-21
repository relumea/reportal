// The Teams panel's Add member control: users already on the team show
// greyed out with a member suffix instead of adding twice.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("a team member shows greyed out in its own Add member control", async ({
  page,
  request,
}) => {
  const created = await request.post("/api/users", { data: { name: "grey-member" } });
  expect(created.ok()).toBeTruthy();
  const user = (await created.json()) as { id: number };
  const added = await request.post(`/api/teams/${state.team.id}/members`, {
    data: { user_id: user.id },
  });
  expect(added.ok()).toBeTruthy();

  await page.goto("/#/users");
  const teams = panelByTitle(page, "Teams");
  const select = teams.getByLabel(`add a member to ${state.team.name}`);
  await expect(select).toBeVisible();
  const option = select.locator("option", { hasText: "grey-member" });
  await expect(option).toBeDisabled();
  await expect(option).toHaveText("grey-member (member)");

  // Removing the member refreshes the open members list itself, and the
  // add-member control offers them again.
  const teamRow = teams.locator("table.data-table tbody tr").filter({ hasText: state.team.name });
  await teamRow.getByRole("button", { name: "Members", exact: true }).click();
  const members = page.locator("h3", { hasText: `${state.team.name} members` });
  await expect(members).toBeVisible();

  // A role change reloads the members list itself: the shield shows without
  // closing and reopening.
  const role = page.getByLabel(`role of grey-member in ${state.team.name}`);
  await role.selectOption("owner");
  const shielded = page
    .locator("table.data-table")
    .filter({ has: page.getByRole("button", { name: "Remove", exact: true }) })
    .locator("tbody tr")
    .filter({ hasText: "grey-member" });
  await expect(shielded.getByText("shield", { exact: true })).toBeVisible();
  await role.selectOption("member");
  const memberTable = page
    .locator("table.data-table")
    .filter({ has: page.getByRole("button", { name: "Remove", exact: true }) });
  const memberRow = memberTable.locator("tbody tr").filter({ hasText: "grey-member" });
  await expect(memberRow).toBeVisible();
  await memberRow.getByRole("button", { name: "Remove", exact: true }).click();
  await memberRow.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(memberTable.locator("tbody tr")).toHaveCount(0);
  await expect(select.locator("option", { hasText: "grey-member" })).not.toBeDisabled();

  const deleted = await request.delete(`/api/users/${user.id}`);
  expect(deleted.ok()).toBeTruthy();
});

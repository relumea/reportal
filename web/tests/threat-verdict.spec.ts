// The threat verdict the binary detail's Threat report and Triage panels
// render: the software-type badge with its signals, the score meter with its
// contributions, and the MITRE technique link.  The seeder stores a threat
// report and a file-type detection, which is what the API derives both from.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// The seeded file-type detection is a UPX packer match, so the classifier names
// the packed-image type and the score counts its packing contribution.
const SEEDED_TYPE = "packed-executable";

test("the threat report renders the software type, the score and the MITRE link", async ({
  page,
}) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const threat = panelByTitle(page, "Threat Report");

  const verdict = threat.locator(".verdict");
  await expect(verdict.locator(".badge", { hasText: SEEDED_TYPE })).toBeVisible();
  await expect(verdict.getByText("signals (", { exact: false })).toBeVisible();

  const meter = threat.locator(".meter");
  await expect(meter.getByText("Threat score", { exact: true })).toBeVisible();
  await expect(meter.locator(".meter-seg[data-lit]").first()).toBeVisible();

  // The score never arrives bare: every point is named with its evidence.
  const contributions = threat.locator("table.data-table").first();
  await expect(contributions.getByText("packing", { exact: true })).toBeVisible();
  await expect(contributions.getByText("indicators", { exact: true })).toBeVisible();

  // reportal's own heuristic, said in the rendered output (the raw JSON below
  // the panel repeats it, so the note is matched as the verdict's paragraph).
  await expect(
    threat.locator("p.muted", { hasText: "reportal's own deterministic heuristic" }).first(),
  ).toBeVisible();

  // The stored row keeps a plain technique id; only the rendered output links.
  const technique = threat.locator('a[href^="https://attack.mitre.org/techniques/"]').first();
  await expect(technique).toBeVisible();
  await expect(technique).toHaveText(/^T\d{4}$/);

  // Hosted Threat Report carries its YARA rule, read from the remediation scan.
  await expect(threat.getByText(/Yara Rule \(notepad_demo\)/)).toBeVisible();

  // Hosted IOC rows carry a copy control on the value.
  await threat.getByText(/Urls \(1\)/).click();
  const ioc = threat.getByText("https://c2.example.com/beacon", { exact: true });
  await expect(ioc).toBeVisible();
  await expect(ioc.locator("xpath=ancestor::li").locator(".copy-row")).toBeVisible();

  // Hosted agent cards rate the result in the header: Up toggles on, Up again
  // clears it, and the suite reverts the journal entry it wrote.
  const panel = page.locator(".panel").filter({
    has: page.getByRole("heading", { name: "Threat Report", exact: true }),
  });
  const up = panel.getByRole("button", { name: "Up", exact: true });
  await expect(up).toHaveAttribute("aria-pressed", "false");
  await up.click();
  await expect(panel.getByRole("button", { name: "Up", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await panel.getByRole("button", { name: "Up", exact: true }).click();
  await expect(panel.getByRole("button", { name: "Up", exact: true })).toHaveAttribute(
    "aria-pressed",
    "false",
  );
});

// The Triage panel renders the same `ThreatVerdict` from its own payload; the
// seeded workspace stores no triage dossier (a triage run needs the engine), so
// that surface is covered by tests/test_classification_api.py, which asserts
// both routes answer identical values for the same stored state.

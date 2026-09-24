// An uploaded binary is analysed on its own: the upload queues the `analyse`
// job, and the binary header follows it.  Bytes no discoverer can read fail
// the analysis, and the header names the reason beside the control that runs
// it again.

import { uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

test("the header shows a failed analysis and queues it again", async ({ page }) => {
  const name = `${uniqueName("e2e-unanalysable")}.bin`;
  const upload = await page.request.post("/api/binaries", {
    multipart: { file: { name, mimeType: "application/octet-stream", buffer: Buffer.from(name) } },
  });
  expect(upload.ok()).toBeTruthy();
  const binary = (await upload.json()) as { id: number; analysis_job: { id: number } | null };
  expect(binary.analysis_job).not.toBeNull();

  await page.goto(`/#/binaries/${binary.id}`);
  const failure = page.locator(".detail-head").getByText(/^Analysis failed: rebrew intake failed/);
  await expect(failure).toBeVisible({ timeout: 60_000 });

  const again = page.locator(".detail-head").getByRole("button", { name: "Analyze again" });
  const queued = page.waitForResponse(
    (response) => response.url().endsWith("/api/jobs") && response.request().method() === "POST",
  );
  await again.click();
  const job = (await (await queued).json()) as { kind: string; binary_id: number };
  expect(job).toMatchObject({ kind: "analyse", binary_id: binary.id });
});

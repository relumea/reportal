// Playwright global teardown: stop the seeded server's process group.  The
// seeded workspace stays under .scratch/ for debugging; the next run rebuilds
// it from scratch.

import { e2eState } from "./e2e-state";
import { stopServerGroup } from "./server";

export default async function globalTeardown(): Promise<void> {
  await stopServerGroup(e2eState().pid);
}

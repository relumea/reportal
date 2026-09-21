# Commercializing the dynamic tier

How the disposable-VM and agent-driven live-debugging capability in
[LIVE_DEBUGGING.md](LIVE_DEBUGGING.md) could make money, against the commercial shape
[FUNDING.md](FUNDING.md) already states (a private SaaS project, Singapore and US entities, beta
with pilots). The static portal is the wedge and the free tier; the dynamic tier is the paid
expansion, because that is the part a customer cannot assemble from free tooling in an evening.

## What is actually sold

Not a debugger. `x64dbg`, `gdb`, `IDA` and WinDbg TTD are free or already owned by the buyer.
What is sold is the layer on top, and it has four parts:

1. **One stored artifact per sample** where static decompilation and live observation are joined
   at the function VA, so a reviewer reads one page instead of stitching two tools.
2. **Provenance**: every claim labelled `observed` or `inferred` and citing the probe that
   produced it, which is what makes the artifact defensible in a report.
3. **An agent that runs the session** and writes the digest, so the expensive human hours
   (reproduce, break, step, note) shrink to review.
4. **Air-gapped and self-hosted operation**, with the customer's own model endpoint, which no
   hosted analysis service can offer.

The hosted competitors sell AI reverse engineering and a dynamic sandbox
([REVENGAI.md](REVENGAI.md) names DRAKVUF behind `portal.reveng.ai`). reportal's differentiator is
not a better debugger, it is custody: the samples, the traces and the model calls stay on the
customer's host.

## Unit economics

The static tier costs almost nothing to serve: engine calls are local and the model is optional.
The dynamic tier has real cost of goods, and it is not tokens:

| Cost | Driver | Control |
|------|--------|---------|
| VM minutes | concurrent sessions times wall clock | caps per session, the `sandbox.Caps` analogue |
| Snapshot and image storage | base images per target family plus overlays | image digest pinning, overlay destroyed at session end |
| Image maintenance | guest hardening and tool updates per family | start with two images (Linux, Windows), not ten |
| Model inference | probes per session, digest generation | the existing credit price from `credits.py` |
| Analyst review | the human half, billed as seats | seat pricing, not usage |

The plan catalog already forbids selling inference below cost:
`plans.MAX_COGS_SHARE` bounds what a tier may spend on the model it resells, and
`tests/test_plans.py` asserts the ceiling rather than the literal numbers. The dynamic tier needs
the same guard for VM minutes, so a session price cannot fall below the hypervisor cost it buys.
That is the one new pricing primitive, and it belongs beside the credit arithmetic, not in a
spreadsheet.

## Packaging against the plan catalog

The catalog in `plans.py` is already shaped for this, because a credit is one reference task
rather than a token count. A debug session is a task family like any other:

- **Free / self-host (`internal`)**: static analysis, no VM tier. A workspace with no hypervisor
  answers `debug-unavailable`, the way `sandbox.require_runner` refuses a missing `bwrap`.
- **Pro**: a small number of sessions per month, one concurrent VM, Linux guest only.
- **Team**: more sessions, concurrent VMs, Windows guest, shared session artifacts and the
  digest in the team's knowledge scope.
- **Enterprise**: a bring-your-own-cloud backend, where the customer's own hypervisor runs the
  guest, reportal only orchestrates over vsock. This is the motion that removes our COGS and our
  custody liability at once, and it is the only honest answer to a customer who will not let a
  sample leave its network.

Metering already records what a metered start spends (`metering.charge_task`,
`usage_events`), so a session charge is a new priced task, not a second accounting system. The
same rule as today holds: an organisation that configures its own model endpoint is not metered
for inference (`plans.metered`), and a self-hosted install is unmetered by construction.

## Buyers and motions

- **IR and DFIR teams**: sell time to verdict. A session that arrives with a digest beside the
  stored decomp shortens the "what does this do" handoff.
- **Regulated and air-gapped analysts** (defence, government, banks, OT): the only pitch that
  matters is custody plus an on-prem deployment. Static tier first, dynamic second.
- **MSSP and MDR providers**: per-sample economics at volume, where the agent does the first
  pass and the analyst reviews. Sell concurrency and session packs, not seats.
- **Product security teams**: SBOM and CVE work that needs a live confirmation (does this path
  actually reach?), which is the `exploitability.py` question answered with observation.
- **Singapore SME pipeline**: `FUNDING.md` item 3, the PSG pre-approval, exists to turn exactly
  these pilots into subsidised purchases. Lead the application with the dynamic tier, since
  Startup SG Tech requires the funded project not to have started yet.

## Compliance gates before selling

- The license blocker in `FUNDING.md` stands first: MIT and a public repo cannot be sold.
- Running a customer's malware needs a DPA, an acceptable-use policy and a no-retention option,
  and the VM tier must be able to refuse a sample the customer cannot legally ship.
- Export control and dual-use review for defensive malware tooling, done once per jurisdiction.
- The two residuals from `LIVE_DEBUGGING.md` become contract language: a hypervisor escape is
  host compromise, and a session reports the path it observed, not what the sample does when
  unobserved. Selling the second as certainty is the liability that ends the product.

## Risks

- **Buyers will not upload samples.** This is the strongest argument for self-host and
  bring-your-own-cloud as the primary packaging, with the hosted tier as the convenience option.
- **Free tooling is good enough.** The answer is the stored, citable, agent-produced artifact and
  the team-shared knowledge scope, never "our debugger is better".
- **A wrong digest is worse than none.** Provenance labelling and probe citations are the product
  feature that limits this, and they are not optional polish.
- **Hypervisor operations are a real burden.** Every guest image is a maintenance commitment, so
  the tier starts with two and grows only on customer demand.

## Milestones to revenue

1. Slices 1 to 3 of `LIVE_DEBUGGING.md` (DAP client, VM backend, trace-to-store join): dogfood on
   the existing pilots, no billing.
2. Slices 4 and 5 (agent worker, Windows guest): first paid pilot, priced per session with the
   VM-minute floor, sold as a report the customer's analyst reviews.
3. Slices 6 to 8 (firmware backend, fusion digest, rename sync): team tier and the enterprise
   bring-your-own-cloud motion, plus the CCDF LOI from `FUNDING.md` item 2 framed around
   the dynamic tier.

## See also

- [LIVE_DEBUGGING.md](LIVE_DEBUGGING.md) for the engineering slices this prices
- [FUNDING.md](FUNDING.md) for the grants and investors that fund the build
- [PARITY.md](PARITY.md) for how the capability maps to the hosted portal
- [THREAT_MODEL.md](THREAT_MODEL.md) for the boundary the VM tier must keep

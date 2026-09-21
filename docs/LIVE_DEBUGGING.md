# Live debugger integration research

How reportal could talk to a live debugger, which protocol to pick first, and where the seam
lands in this tree. Swept 2026-09-21 from the public protocol specs and the integration
shims other tools already ship. reportal today has no live-debugger seam: static scans read
stored bytes through `engines.py`, and `sandbox.py` is the only module that executes a sample
(bounded detonation, boundary 7 in `docs/THREAT_MODEL.md`). A debugger would be the second
execution path, and a disposable VM the third, so both inherit that opt-in posture. Static
scans stay the default: a debug session adds evidence to a stored analysis, it never replaces
one.

## What the protocols offer

| Protocol | Speaks to | Control surface | Evidence |
|----------|-----------|-----------------|----------|
| Debug Adapter Protocol (DAP) | Any DAP server (`lldb-dap`, `debugpy`, C/C++ extensions) | One JSON protocol for launch/attach, breakpoints, threads, stack frames, variables, evaluate, step | [DAP specification](https://microsoft.github.io/debug-adapter-protocol/specification.html), [official page](https://microsoft.github.io/debug-adapter-protocol/) |
| GDB Remote Serial Protocol (RSP) plus GDB/MI | `gdbserver`, QEMU `gdbstub`, firmware stubs, `rr` replay | `target remote` sessions, register and memory read/write, breakpoints, MI records for tool control | [GDB remote targets](https://www.sourceware.org/gdb/5/onlinedocs/gdb.pdf), [TRACE32 RSP note](https://support.lauterbach.com/kb/articles/pdf/does-trace32-support-the-gdb-remote-serial-protocol-rsp) |
| LLDB (`SB` API, `lldb-server`, `lldb-dap`) | Local and remote Darwin/Linux processes | Scriptable breakpoints, memory and register reads, `lldb-dap` as the DAP front end | [lldb-dap usage](https://lldb.llvm.org/use/lldbdap.html), [lldb-dap tree](https://cos.googlesource.com/mirrors/github.com/llvm/llvm-project/+/0b8c8ed04211dae629811f24e6033e5c2185508f/lldb/tools/lldb-dap) |
| WinDbg `DbgEng` (`IDebugClient` and peers) | User-mode, kernel, crash dumps, Time Travel Debugging | Remote sessions, symbol-driven inspection, TTD replay | [Remote debugging with WinDbg](https://learn.microsoft.com/de-ch/windows-hardware/drivers/debugger/remote-debugging-using-windbg) |
| `rr` record and replay | Linux user-mode traces | Deterministic replay over a GDB/MI-compatible interface | [rr project](https://rr-project.org/) |

## What other tools already proved

Running debuggers through agent-shaped seams is established. `windbg-mcp` exposes live
user-mode, kernel, dump and TTD sessions as MCP tools over stdio
([repo](https://github.com/glslang/windbg-mcp)). `karellen-rr-mcp` exposes `rr`
record, replay and inspection through GDB/MI
([repo](https://github.com/karellen/karellen-rr-mcp)). `ret-sync` synchronizes a live
WinDbg/GDB/LLDB/x64dbg session with IDA, Ghidra or Binary Ninja
([repo](https://github.com/kar98kar/ret-sync)). The Visual Studio MIEngine already drives
any MI-enabled debugger (GDB, LLDB, clrdbg) from one DAP-adjacent engine
([repo](https://github.com/smx-smx/MIEngine)). The pattern that transfers: one
editor-neutral protocol in front, native engines behind.

## Recommendation for reportal

DAP first, RSP second, `DbgEng` never in-process. DAP covers GDB and LLDB through existing
servers (`lldb-dap` for native binaries, a GDB DAP shim or QEMU `gdbstub` for firmware and
packed samples), so reportal writes one client instead of two wire protocols. RSP stays the
fallback for stubs no DAP server fronts (bare-metal firmware, `rr` replay). `DbgEng` is
Windows-only and COM-shaped; if a Windows target ever needs it, front it with the same DAP
shape from another process rather than linking it into the portal.

The seam mirrors `sandbox.py`: a `reportal.debug_backends` entry-point group beside the
`sandbox_runners` one, off until `REPORTAL_DEBUG=enabled` (or `[debug] enabled = true`),
with the runner argv, caps and run ledger reused rather than reinvented. Debug sessions run
as `jobs.py` kinds (launch, step, read, stop) so a client polls instead of holding a
request open, and their outputs land as stored scans (register dump, breakpoint hit log,
single-step trace, coverage delta against `recoverage`), never as live process handles in
the store. MCP exposure follows the `agent.py` gate: memory and register reads are
read-only tools, while step, continue and write are destructive and pause for
`POST .../confirm`. The threat model delta is one paragraph in `docs/THREAT_MODEL.md`:
a debugger executes the sample under control, so it carries boundary 7 verbatim (opt-in,
installed backend, caps, unshared network, recorded run) plus two debugger-only residuals
(an attached process can be anti-debug aware, and a breakpoint trace can grow without
bound unless capped like `MAX_OUTPUT_BYTES`).

## The disposable VM tier

`sandbox.py` runs a sample in `bwrap` on the host kernel, and its own residual says there is
no seccomp, no syscall log and no VM. A debugger makes that gap load-bearing: a session is a
controlled execution of malware, and a Windows PE cannot be debugged by a host process at
all. The tier that closes both is one disposable virtual machine per session, with the
hypervisor as the containment boundary.

Lifecycle:

- A base image per target family (a Linux guest, a Windows guest) is pinned by digest in
  settings (`REPORTAL_DEBUG_IMAGE` or `[debug] image`), never by a moving tag.
- One overlay clone per session off that image, a `qcow2` backing file or the hypervisor's
  own snapshot, so the base stays immutable and two sessions cannot see each other.
- The clone is destroyed on every exit path, including a backend exception, which is the
  `finally` discipline `sandbox.execute` already keeps.
- Memory, vCPU, disk and wall clock are capped the way `sandbox.Caps` caps a detonation,
  and a session that outlives its window is killed by domain destroy, not by a signal to a
  process group.

Transport: the guest gets no network device. The control channel is `virtio-vsock` (else
`virtio-serial`), so the DAP or RSP stream never leaves the host and the guest has no route
at all. Lifecycle calls (create, clone, destroy) go through `qemu-guest-agent`. That keeps
the property `BwrapRunner.argv` already reports as `network: unshared` while giving the
guest an operating system of its own.

Guest payload, one per target:

- Linux: `lldb-dap` or `gdbserver` in the guest, driven by the DAP client above.
- Windows: WinDbg/`DbgEng` in the guest behind a DAP shim, in its own process rather than
  linked into the portal.
- Firmware: `qemu -gdb` over a region `firmware.py` already carved.
- Replay: `rr` where the guest kernel permits it, else an in-guest snapshot before each
  risky step, which is what makes a session re-readable after it ends.

Seam: a `Backend` protocol in a `reportal.debug_backends` entry-point group beside
`sandbox_runners`, with `open`, `attach`, `step`, `read` and `close`. It does not subclass
`Runner`: a detonation is one argv and one exit code, while a debug session is a stateful
conversation. The ledger reuses the run-table shape in a `debug_sessions` table (backend,
image digest, caps, status, probe count, transcript, notes), statuses `running`, `finished`
and `failed`, and the same one-live-row-per-binary unique index the sandbox uses so a
double-click cannot start two sessions on one sample.

## The AI agent loop

`agent.py` already proves the shape: the model picks tools from the MCP registry, its calls
are schema-validated, `MAX_TOOL_CALLS` bounds the loop, a destructive tool pauses for
`POST /api/conversations/<id>/confirm`, and cancel lands at a step boundary. A debugger is
the strongest version of that pattern (the actuator can execute and mutate a sample), so it
reuses the gate rather than inventing a second one.

The loop itself belongs where `auto_workers` puts a worker, not in a chat: a `debug_probe`
worker takes a hypothesis, picks a probe, runs it on the live session and records what it
observed. Concretely:

- The model is given the stored decompilation, the function list with VAs and the
  disassembly, so it names stored addresses instead of guessing them.
- Its tools are the session surface: `debug_launch`, `debug_attach`, `debug_breakpoint`,
  `debug_step`, `debug_read_memory`, `debug_registers`, `debug_backtrace`, `debug_resume`,
  `debug_snapshot`, `debug_close`. Reads carry `readOnlyHint`; breakpoint, step, resume,
  write and close are destructive and pause for confirmation.
- Every probe is recorded on the session row with its arguments and its result, so a run
  replays deterministically and a claim can be traced to the probe that produced it.
- Probes, model calls and tokens are bounded and metered (`metering.charge_task` on the SaaS
  profile), because a model with a debugger can burn both time and credits quickly.

## Fusion: stored decompilation plus live observation

The join key is the function VA, which reportal already stores. A live session adds facts a
static scan cannot reach:

- Which stored functions the sample actually executed, and how often.
- Which basic blocks ran, checked against the CFG edges
  `rebrew.build_cfg_payload` already returns, so uncovered edges become a real coverage
  number rather than a similarity estimate.
- Argument and return values at breakpoints, which resolve what an indirect call target
  actually was.
- API and syscall calls with their arguments, which is evidence stronger than the import
  table: a statically imported API that never fires is not behavior.

Two rules keep that honest, and both follow the existing `threat.py` line that a heuristic is
not proof:

- Every derived claim is labelled `observed` or `inferred`. A `behavior.py` finding backed by
  a live call becomes `observed`; everything else stays `inferred`, and a scan's confidence
  never upgrades from a single session.
- One session is one path, not a specification. A function that never ran is `unobserved`,
  which is not the same as absent and is not reported as a negative.

Storage: the session writes a `debug-session` scan through `store.set_scan`, per-function
observed facts land beside the existing extras in `function_extras.py`, and the model's digest
is an `ai_artifacts` row of kind `debug-digest`, one claim per row entry, each citing its
probe id and VA. A digest a reader cannot check is not worth storing.

## Ingest

The last mile is the part the rest of the portal already has:

- The rendered transcript and digest pass through `knowledge.ingest_document` scoped to the
  binary, so `knowledge.retrieve`, the conversations scope and the docs assistant cite the
  session the way they cite an ingested report.
- Observed facts become `graph_nodes` and `graph_edges` in `graph.py` (a function hit, an
  API called at runtime, an IOC seen in a string argument), so one graph query crosses static
  and live evidence and a plugin backend such as Cognee can carry both.
- Because the session row is journaled the way a `sandbox_runs` row is, a revert removes the
  record. What the sample did while it ran is compensated by domain destroy, which is the
  same honest boundary `docs/THREAT_MODEL.md` already states for detonation.

## Guards this tier adds

- Off by default: `REPORTAL_DEBUG`, then `[debug] enabled`. A workspace with no hypervisor or
  no registered backend answers `debug-unavailable`, the way `require_runner` refuses a
  missing `bwrap`.
- A pinned image digest, no guest network device, and vsock as the only channel.
- Caps on wall clock, memory, vCPU, steps, breakpoints and transcript bytes, the analogue of
  `MAX_OUTPUT_BYTES` and `MAX_FILES`.
- One live session per binary, enforced by an index rather than by a check.
- The residual this tier cannot remove, stated rather than hidden: a hypervisor escape is host
  compromise, the agent is a model driving a debugger behind a confirmation gate, and a
  sample can detect that it is being debugged and change behavior, so a session reports what
  it saw on that path and not what the sample does when unobserved.

## Smallest useful slices, in order

1. Read-only DAP client: attach, break, read registers and memory, detach; results stored as
   a `debug-session` scan. Effort S.
2. Disposable-VM backend for a Linux guest: pinned image, overlay clone, vsock channel,
   `debug_sessions` ledger, teardown on every path. Effort M.
3. Trace-to-store join: hits resolved to stored function VAs, CFG edge coverage, per-function
   observed facts. Effort M.
4. `debug_probe` agent worker over the MCP registry, with the confirmation gate and probe
   recording. Effort M.
5. Windows guest with a DAP shim in front of `DbgEng`, which is the slice that reaches PE
   malware. Effort M.
6. QEMU `gdbstub` backend for firmware images `firmware.py` already carves. Effort S.
7. Fusion digest: the `debug-digest` artifact, `observed` versus `inferred` labelling, the
   knowledge ingest and the graph nodes. Effort M.
8. `ret-sync`-shaped rename sync: push stored renames into the session, pull session labels
   back as proposals, never as silent overwrites. Effort S.


## Deliberately out of scope

Kernel debugging, TTD hosting, and a built-in debugger or hypervisor: reportal orchestrates
installed backends the way it orchestrates `bwrap`, it does not become one. Image building is
the operator's (`libvirt`/QEMU/KVM plus a guest the operator hardened), and a VM is not a
stronger promise than the host it sits on. Dynamic-only behavior stays where
`docs/RESEARCH_ROADMAP.md` already put it: recorded as stored evidence, not reproduced as a
hosted-graph claim.

## See also

- [COMMERCIALIZATION.md](COMMERCIALIZATION.md) for how this tier is packaged and sold

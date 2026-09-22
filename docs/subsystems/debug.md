# Live debug sessions

Sources: src/reportal/debug.py

The read-only live-debugger seam, and the second execution path beside detonation. A session is
refused unless the workspace opts in and an installed backend exists, and every session is bounded
and recorded: the backend, the caps, the transcript and the stored scan. `lldb-dap` speaks DAP,
`gdb` speaks MI (or drives `qemu-<arch>` through `target remote` with `--qemu`); the probe
reads threads, one frame, registers and a memory window, then disconnects.
Nothing is stepped, continued or written.

## Vocabulary

- `Backend(name, executable, hint, describe)`: `path()` and `available()` report installation.
  `register_backend` and `unregister_backend` are the registry, with the built-in unremovable.
- `Caps(timeout_seconds)`: `requested_caps` validates a request against
  `DEFAULT_TIMEOUT_SECONDS`/`MAX_TIMEOUT_SECONDS`; reads cap at `MAX_READ_BYTES`, breakpoints at
  `MAX_BREAKPOINTS`, the transcript at `MAX_TRANSCRIPT_BYTES`.
- The session table is `debug_sessions`, with statuses `running`, `finished` and `failed`. At most
  one `running` row per `binary_id` (`idx_debug_sessions_live_binary`); a second session while
  live reuses that row.
- `DebugError.code`: `debug-disabled`, `debug-unavailable`, `invalid-debug`, `no-debug-session`.
- The transcript is stored as the `debug-session` scan (`SCAN_KIND_DEBUG_SESSION`).
- `observed_coverage` joins the newest session's addresses to the stored functions by VA
  containment; untouched functions are `unobserved`, never absent.
- `session_proposals` joins frame names to stored functions by VA (source `debug`);
  person-authored names are never proposed and `apply_session_proposal` renames explicitly.

## Wiring

- Routes: `POST`/`GET /api/binaries/{binary_id}/debug-session` (body `qemu_arch` selects the
  stub), `GET .../debug-session/status`, `GET .../debug-coverage` and
  `GET .../debug-proposals` (both stored-only), `POST /api/functions/<id>/debug-apply`.
- CLI: `debug-session` (`--coverage`, `--qemu`), `debug-proposals`, `debug-apply`. MCP:
  `run_debug_session`, `get_debug_session`, `get_debug_status`, `get_debug_coverage`,
  `get_debug_proposals`, `apply_debug_proposal`. Jobs: the `debug` kind.
- Settings: `REPORTAL_DEBUG` or `[debug] enabled`, `REPORTAL_DEBUG_BACKEND` or `[debug] backend`.
  A third party registers through the `reportal.debug_backends` entry-point group.
- `run_session` is the shared orchestration the route, CLI, MCP tool and job call, so the
  guards are checked once. The session, its scan and its knowledge digest are journaled, so a
  revert removes the record; the graph rebuild links the digest through the VA-mention edge.

## Invariants

- With the workspace not opted in, every path refuses with `debug-disabled`; with no installed
  backend, with `debug-unavailable` (`tests/test_debug.py`).
- A requested timeout outside the absolute caps is refused as `invalid-debug` rather than clamped
  silently (`tests/test_debug.py`).
- The session row is written before the probe starts, and a second session while one is still
  `running` reuses that row without starting another probe (`tests/test_debug.py`).
- `unregister_backend` refuses an unknown name and the built-in backend (`tests/test_debug.py`).

## See also

- [ARCHITECTURE.md: Sandbox detonation](../ARCHITECTURE.md#sandbox-detonation)
- [LIVE_DEBUGGING.md](../LIVE_DEBUGGING.md)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
- [CONFIG.md](../CONFIG.md)

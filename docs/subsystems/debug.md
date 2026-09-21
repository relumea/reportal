# Live debug sessions

Sources: src/reportal/debug.py

The read-only live-debugger seam, and the second execution path beside detonation. A session is
refused unless the workspace opts in and an installed backend exists, and every session is bounded
and recorded: the backend, the caps, the DAP transcript and the stored scan. The probe launches
the sample stopped, waits for the entry stop, reads the thread list, one stack frame, the
general-purpose registers and a bounded window at the instruction pointer, then disconnects.
Nothing is stepped, continued or written.

## Vocabulary

- `Backend(name, executable, hint, describe)`: `path()` and `available()` report installation.
  `lldb-dap` and `gdb` are the shipped backends; `register_backend` and `unregister_backend` are
  the registry, with the built-in backend unremovable.
- `Caps(timeout_seconds)`: `requested_caps` validates a request against
  `DEFAULT_TIMEOUT_SECONDS`/`MAX_TIMEOUT_SECONDS`; reads cap at `MAX_READ_BYTES`, breakpoints at
  `MAX_BREAKPOINTS`, the transcript at `MAX_TRANSCRIPT_BYTES`.
- The session table is `debug_sessions`, with statuses `running`, `finished` and `failed`. At most
  one `running` row per `binary_id` (`idx_debug_sessions_live_binary`); a second session while
  live reuses that row.
- `DebugError.code`: `debug-disabled`, `debug-unavailable`, `invalid-debug`, `no-debug-session`.
  `status_payload` reports the opt-in, the backends, the caps, the session count and the last
  session.
- The transcript is stored as the `debug-session` scan (`SCAN_KIND_DEBUG_SESSION`).

## Wiring

- Routes: `POST`/`GET /api/binaries/{binary_id}/debug-session`,
  `GET /api/binaries/{binary_id}/debug-session/status`.
- CLI: `debug-session`. MCP: `run_debug_session`, `get_debug_session`, `get_debug_status`.
- Settings: `REPORTAL_DEBUG` or `[debug] enabled`, `REPORTAL_DEBUG_BACKEND` or `[debug] backend`.
  A third party registers through the `reportal.debug_backends` entry-point group.
- `run_session` is the shared orchestration the route, the CLI and the MCP tool call, so the
  guards are checked once. The session and its scan are journaled, so a revert removes the record.

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

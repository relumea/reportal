# Sandbox detonation

Sources: src/reportal/sandbox.py

The detonation seam: it runs a stored sample free (the debugger in `debug.py` controls
one instead). Detonation is refused unless the workspace opts in and an installed
runner exists, and every run is bounded and recorded: the caps in force, the exit
status, the duration, bounded output tails and the files the sample left behind.

## Vocabulary

- `Runner(name, executable, hint, describe)`: `path()` and `available()` report installation, and
  `argv(sample, work, caps)` builds the complete command line. `BwrapRunner` is the shipped
  runner; `RUNNERS`, `BUILTIN_RUNNER`, `register_runner` and `unregister_runner` are the registry.
- `Caps(timeout_seconds, memory_mb, cpu_seconds, file_mb)`: `requested_caps` validates a request
  against `DEFAULT_TIMEOUT_SECONDS`/`MAX_TIMEOUT_SECONDS` and `DEFAULT_MEMORY_MB`/`MAX_MEMORY_MB`,
  and `as_payload()` reports the fixed facts (unshared network, read-only root, one writable
  directory).
- The run table is `sandbox_runs`, with statuses `running`, `finished`, `timed_out` and `failed`.
  At most one `running` row per `binary_id` (`idx_sandbox_runs_live_binary`); a second detonation
  while live reuses that row. Output is bounded by `MAX_OUTPUT_BYTES` and the file list by
  `MAX_FILES`.
- `SandboxError.code`: `sandbox-disabled`, `sandbox-unavailable`, `invalid-sandbox`, `no-run`.
  `status_payload` reports the opt-in, the runners, the caps, the run count and the last run.

## Wiring

- Routes: `POST`/`GET /api/binaries/{binary_id}/dynamic-execution`,
  `GET /api/binaries/{binary_id}/dynamic-execution/status`,
  `GET /api/analyses/{analysis_id}/dynamic-execution` and its `/status`.
- CLI: `sandbox`. MCP: `run_sandbox_detonation`, `get_sandbox_report`, `get_sandbox_status`.
- Settings: `REPORTAL_SANDBOX` or `[sandbox] enabled`, `REPORTAL_SANDBOX_RUNNER` or `[sandbox]
  runner`. A third party registers through the `reportal.sandbox_runners` entry-point group.
- `detonate_binary` is the shared orchestration the route, the CLI and the MCP tool call, so the
  guards are checked once. The run is journaled, so a revert removes the record.

## Invariants

- With the workspace not opted in, every path refuses with `sandbox-disabled`; with no installed
  runner, with `sandbox-unavailable` (`tests/test_sandbox.py`).
- A requested timeout or memory size outside the absolute caps is refused as `invalid-sandbox`
  rather than clamped silently (`tests/test_sandbox.py`).
- The run row is written before the process starts, and the process group is killed on the
  wall-clock timeout (`tests/test_sandbox.py`).
- A second detonation while a run is still `running` reuses that row without executing again;
  a crash-left `running` row past `MAX_TIMEOUT_SECONDS` plus `LIVE_STALE_GRACE_S` is abandoned so
  a later claim is not blocked forever (`tests/test_sandbox.py`).
- `BwrapRunner.argv` is a pure list carrying `--unshare-all`, `--die-with-parent`,
  `--new-session`, `--clearenv`, a read-only host root and one writable bind
  (`tests/test_sandbox.py`).
- `unregister_runner` refuses an unknown name and the built-in runner, and `register_runner`
  replaces a same-named entry while keeping the earliest origin (`tests/test_sandbox.py`).
- Output tails and the work-directory file list are capped, and the file list reports whether it
  was truncated (`tests/test_sandbox.py`).

## See also

- [ARCHITECTURE.md: Sandbox detonation](../ARCHITECTURE.md#sandbox-detonation)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
- [CONFIG.md](../CONFIG.md)

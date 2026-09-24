# Engines

Sources: src/reportal/engines.py, src/reportal/rebrew_import.py

This subsystem owns the one adapter over the `rebrew` engine: importing it, calling it and naming
its failures. No call leaks a traceback: a broken install is `EngineUnavailable`, any other failure
a bounded `EngineError`. It also turns rebrew projects into portal rows.

## Vocabulary

- `RebrewEngine`: JSON methods return the parsed object unchanged, `disassemble` text. Methods: `fingerprint`, `imports`, `strings`, `analyze`,
  `crypto_scan`, `pe_info`, `identify_library`, `report`, `decompile`, `xrefs`, `describe`,
  `structs`, `read_memory`, `read_memory_page`, `security_scan`, `disassemble`,
  `control_flow_graph`, `test_source`, `lzexe_version`, `unpack_lzexe`, `intake`,
  `build_coverage_db`, `library_functions`.
- `intake`: `rebrew intake` as a child process in the project dir (it works in its cwd, which
  job threads share), bounded by `INTAKE_TIMEOUT_SECONDS`, then `build_coverage_db`.
- `rebrew_import`: `import_project` (`import-rebrew`), `analyse_binary` (the `analyse` job: intake
  into `projects/<sha256>`, then the import, stamping the target ISA).
- `EngineError`, `EngineUnavailable` (rebrew not importable), `UnmappedAddressError` (an
  address with no raw bytes).
- `available()` is process-level; `enabled` pins either side; `origin` names the installed
  package.
- `ERROR_MESSAGE_CHARS` (400) bounds an engine message.
- Read bounds: `MEMORY_READ_DEFAULT` 64 and `MEMORY_READ_MAX` 1024; `MEMORY_PAGE_DEFAULT` 256 and
  `MEMORY_PAGE_MAX` 4096; `MEMORY_BYTES_PER_ROW` 16; `MEMORY_ADDRESS_KINDS` (`va`, `rva`,
  `file`).
- Closed vocabularies: `DISASM_FORMATS` (`nasm` only for `NASM_ARCH`, `asm` for any ISA;
  `listing_format(arch)` picks the cached one), `DECOMPILER_BACKENDS` with
  `DEFAULT_DECOMPILER_BACKEND` `kuna`, and `SECURITY_SEVERITIES` with
  `DEFAULT_SECURITY_MIN_SEVERITY` `low`.
- `kuna_spec_dir()`: kuna.s SLEIGH specs (`KUNA_SPECS`, else discovered); `get_engine` /
  `set_engine`: the process-wide accessor tests inject.

## Wiring

- The scan modules, the pipeline, `auto_llm_worker.py` and the jobs registry call `get_engine()`.
- Routes `GET /api/binaries/<binary_id>/memory` and `GET /api/binaries/<binary_id>/memory/page`
  are the direct byte-read surfaces; CLI `memory`, `memory-page`, `disasm`, `strings`,
  `fingerprint` and `security-scan`; MCP tools `read_memory` and `get_xrefs`.
- `report` writes into `_paths.reports_dir(binary_id)`, never the rebrew project.
- A missing engine makes the engine routes answer 503 `engine-unavailable`.
- An upload queues `analyse` per new binary; the header shows and re-queues it.

## Invariants

- A raising or exiting engine call becomes a bounded `EngineError`; an `ImportError` or a missing
  package becomes `EngineUnavailable`, and `UnmappedAddressError` subclasses `EngineError`
  (`tests/test_engines.py`).
- `_require_file` and `_require_project` refuse a missing binary or a project without
  `rebrew-project.toml` before any engine call.
- `read_memory` refuses a length outside `1..MEMORY_READ_MAX`, an unknown address kind, a
  negative address, and a window that runs past the section's raw bytes.
- `decompile` and `structs` reject an unknown decompiler backend before the engine runs.
- The engine never parses a PE for bytes: `pe_info` supplies the section map.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#engine-contract)
- [API.md](../API.md)

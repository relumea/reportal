# Engines

Sources: src/reportal/engines.py

This subsystem owns the one adapter over the in-process `rebrew` engine: how it is imported, how
its entry points are called, and how its failures are named. The contract is that no call leaks
an engine traceback: a broken install answers `EngineUnavailable` and every other engine failure
becomes a bounded `EngineError`.

## Vocabulary

- `RebrewEngine`: the adapter. JSON methods return the engine's parsed object unchanged;
  `disassemble` returns text. Methods: `fingerprint`, `imports`, `strings`, `analyze`,
  `crypto_scan`, `pe_info`, `identify_library`, `report`, `decompile`, `xrefs`, `describe`,
  `structs`, `read_memory`, `read_memory_page`, `security_scan`, `disassemble`,
  `control_flow_graph`, `test_source`, `lzexe_version`, `unpack_lzexe`.
- `EngineError`, `EngineUnavailable` (rebrew is not importable), `UnmappedAddressError` (an
  address not backed by the image's raw bytes).
- `available()` is process-level and `enabled` pins either side; `origin` names the installed
  package.
- `ENGINE_UNAVAILABLE_HINT` and `ERROR_MESSAGE_CHARS` (400) bound the message an operator sees.
- Read bounds: `MEMORY_READ_DEFAULT` 64 and `MEMORY_READ_MAX` 1024; `MEMORY_PAGE_DEFAULT` 256 and
  `MEMORY_PAGE_MAX` 4096; `MEMORY_BYTES_PER_ROW` 16; `MEMORY_ADDRESS_KINDS` (`va`, `rva`,
  `file`).
- Closed vocabularies: `DISASM_FORMATS`, `DECOMPILER_BACKENDS` with
  `DEFAULT_DECOMPILER_BACKEND` `kuna`, and `SECURITY_SEVERITIES` with
  `DEFAULT_SECURITY_MIN_SEVERITY` `low`.
- `get_engine` / `set_engine`: the process-wide accessor tests inject through.

## Wiring

- The scan modules, the pipeline, `auto_llm_worker.py` and the jobs registry call `get_engine()`.
- Routes `GET /api/binaries/<binary_id>/memory` and `GET /api/binaries/<binary_id>/memory/page`
  are the direct byte-read surfaces; CLI `memory`, `memory-page`, `disasm`, `strings`,
  `fingerprint` and `security-scan`; MCP tools `read_memory` and `get_xrefs`.
- `report` writes into `_paths.reports_dir(binary_id)`, never into the rebrew project.
- A missing engine makes the engine routes answer 503 `engine-unavailable`.

## Invariants

- A raising or exiting engine call becomes a bounded `EngineError`; an `ImportError` or a missing
  package becomes `EngineUnavailable`, and `UnmappedAddressError` subclasses `EngineError`
  (`tests/test_engines.py`).
- `_require_file` and `_require_project` refuse a missing binary or a directory without
  `rebrew-project.toml` before the engine is called (`tests/test_engines.py`).
- `read_memory` refuses a length outside `1..MEMORY_READ_MAX`, an unknown address kind, a
  negative address, and a window that runs past the section's raw bytes.
- `decompile` and `structs` reject an unknown decompiler backend before the engine runs.
- The engine never parses a PE for bytes: the section map comes from `pe_info`
  (`tests/test_memory.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#engine-contract)
- [API.md](../API.md)

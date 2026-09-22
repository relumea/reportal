# Symbols, signatures and data types

Sources: src/reportal/symbols.py, src/reportal/pdb.py, src/reportal/signatures.py, src/reportal/data_types.py

This subsystem owns the editable models reportal keeps over what it read or was told: debug-symbol
ingestion, the per-function signature model, and the data-type model with its C rendering. The
parsers write nothing and carry a `notes` list saying what they did not do; only
`symbols.import_symbols`, the signature edits and the data-type edits write, and each mutation
records the state it replaced.

## Vocabulary

- `symbols`: `TABLE` (`symbol_files`), sources `elf`, `dwarf`, `pdb`, and `SYMBOL_NAME_SOURCE`
  (`symbol`). `parse` dispatches on the file magic; `parse_elf`, `parse_dwarf` and
  `pdb.read_symbols` are the readers. Bounds: `MAX_SYMBOLS`, `MAX_TYPES`, `MAX_MEMBERS`,
  `MAX_TYPE_DEPTH`. `export_binary` rewrites the store's non-placeholder names into the file's own
  tables: `MAX_EXPORT_ROWS` caps both report lists, `EXPORT_NOTE` states the ceiling,
  `export_file_name` is `<stem>.sym<suffix>`, and `ExportFormatError` is `unsupported-format`.
- `pdb.CONTAINER_MAGIC` is the MSF 7.0 superblock. Only public and procedure symbols are read, so
  `types` is always empty and an unmapped segment answers `va: None`.
- `signatures`: `function_signatures` and `signature_history`. A parameter carries `index`, `type`,
  `name` plus optional `at`, `kind` (`PARAMETER_KINDS`) and `bits`. `default_at` is the convention
  table's answer. `SOURCE_DECOMPILATION`, `SOURCE_MANUAL`, `SOURCE_REVERT`. Either history view
  carries `actor_name` and a relative `age` (`store.history_actor_names`, `clock.relative_age`).
- `data_types`: `data_types` and `data_type_history`. `KINDS` is `struct`, `union`, `enum`,
  `typedef`, `pointer`, `array`, `function`; a bitfield is a member property (`bits`), not a kind.
  `POINTER_SIZE` and `ENUM_SIZE` are 4, a gap member is `GAP_PREFIX`, and each source maps to a
  label through `SOURCE_MAP`. A history view carries `actor_name` (the display name of
  `actor_user_id`, null when that user row is gone) and a relative `age` beside the stored
  `actor` login name and `created_at`, so attribution survives a user delete the way the login
  name does.

## Wiring

- Routes: `POST`/`GET /api/binaries/<id>/symbols`, `GET .../symbols/export`,
  `GET`/`POST .../binary-export`; `GET .../data-types`,
  `POST .../data-types/import`, `POST .../data-types/export`, `PATCH`/`DELETE /api/data-types/<id>`,
  its member, value and history routes; `GET /api/binaries/<id>/signatures`,
  `POST .../signatures/import`, `POST .../signatures/export`,
  `GET`/`PATCH /api/functions/<id>/signature` and
  its parameter and history routes.
- CLI: `symbols`, `symbols-status`, `symbols-export`, `binary-export`, `data-types-import`,
  `data-type-functions`,
  `signatures`, `signatures-import`, `signatures-export`, `signature`, `signature-set`,
  `signature-param*`, `signature-history`, `signature-revert`.
- MCP: `import_symbols`, `get_symbols`, `export_symbols`, `export_binary`, `list_data_types`,
  `import_data_types`,
  `edit_data_type`, `export_data_types`, `get_data_type_history`, `get_signature`,
  `list_signatures`, `run_signature_import`, `edit_signature`, `export_signatures`.

## Invariants

- An unknown type is size 0 with a note naming it. `tests/test_data_types.py`.
- Removing the last member is refused (`EmptyStructError`); a definition that matches no shape
  raises `DefinitionError` and the import records it as a skip with the reason.
  `tests/test_data_types_edits.py`.
- A kind switch recomputes the new kind's shape and the history entry records the members it
  replaced, so a revert restores them. `tests/test_data_type_history.py`.
- `move_parameter` recomputes every placeable `at`; a location the table cannot place keeps its
  value. `tests/test_signatures.py`.
- `export_prototypes` orders by name then function id, so the same model renders the same bytes.
  `tests/test_signatures.py`.
- A DWARF form the reader cannot size ends the unit with a note instead of desyncing the stream.
  `tests/test_symbols.py`.
- An export rewrites only a name that fits its existing slot, never grows one and never touches
  the stored file, and a placeholder store name never replaces a real symbol.
  `tests/test_symbols.py`.

## See also

- [ARCHITECTURE.md, Debug symbols](../ARCHITECTURE.md#debug-symbols)
- [ARCHITECTURE.md, Data types](../ARCHITECTURE.md#data-types)
- [DATA_MODEL.md](../DATA_MODEL.md)

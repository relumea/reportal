# Adding a store table

Prerequisites: read [store.py](../../src/reportal/store.py) (`_SCHEMA`, `init_db`, `connect`,
`_upgrade_schema`, `_ADDED_COLUMNS`, `_ADDED_INDEXES`) and
[DATA_MODEL.md](../DATA_MODEL.md#data-model).

## Steps

1. Add the `CREATE TABLE IF NOT EXISTS` statement to `_SCHEMA` in `src/reportal/store.py`, beside
   the other tables and in dependency order (a table that references another comes after it). Use
   `INTEGER PRIMARY KEY AUTOINCREMENT` for the id, `TEXT` for times, and `NOT NULL DEFAULT` for
   every column an older row would lack.
2. Add the indexes the table's reads need to `_SCHEMA` when the columns exist there, or to
   `_ADDED_INDEXES` when the index depends on a column `_ADDED_COLUMNS` adds. An index statement is
   idempotent (`IF NOT EXISTS`).
3. For a column added to an existing table rather than a new table, add a `(table, column,
   declaration)` tuple to `_ADDED_COLUMNS`. `_upgrade_schema` runs `ALTER TABLE ... ADD COLUMN` for
   a database that predates it, and a fresh database gets the column from `_SCHEMA`. Pick a default
   that reads as "not recorded" rather than inventing a value.
4. Write the CRUD functions at the module level with fully typed parameters and returns, grouped
   under a `# ── <Thing> ──` comment banner:

   ```python
   def add_import_cache(conn: sqlite3.Connection, *, function_id: int, payload: str) -> int:
   ```

   `add_*` returns the new id, `get_*` returns `dict[str, Any] | None`, `list_*` returns
   `list[dict[str, Any]]`, and `set_*`/`clear_*`/`delete_*` return what the caller needs. A row the
   caller cannot find answers `None` rather than raising.
5. Journal a write that must be revertible. A route or CLI write wraps it in
   `journal.journaled_rows(conn, log, table=..., where=..., params=..., description=...)`; a
   pipeline stage records an effect descriptor instead
   (`docs/cookbook/adding-a-component.md`).
6. Describe the table in `docs/DATA_MODEL.md`: what one row is, its key, its writer and the cap on
   a read. State the current shape; do not narrate the migration.
7. Extend `tests/test_store.py` with the CRUD round trip and, for a schema change to an existing
   database, a case that runs `store.init_db` over a fixture database that predates the column, as
   `TestSchemaUpgrade` does.

## Verify

1. `.venv/bin/python -m pytest tests/test_store.py -q` proves the schema, the upgrade path and the
   CRUD functions.
2. `.venv/bin/python -m pytest tests/test_error_docs.py -q` when the new writes answer new error
   codes.
3. `.venv/bin/reportal config` reports the new table count through `instance.describe`, which is
   what proves `init_db` created it on a real workspace.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#store)
- [DATA_MODEL.md](../DATA_MODEL.md)

# Adding a setting

Prerequisites: read [settings.py](../../src/reportal/settings.py) (`Setting`, `SETTINGS`,
`BY_NAME`, `report`, `problems`, `KIND_*`), the `reportal config` command in
[cli.py](../../src/reportal/cli.py), and [ARCHITECTURE.md](../ARCHITECTURE.md#configuration).

## Steps

1. Add the reader. A setting is resolved by a function in the module that owns the concern, not by
   `settings.py`. `auth.required`, `profiles.current` and
   `graph_backends.configured_backend_name` are examples. Put the environment variable name and the
   workspace table and key beside the reader as module constants, as `auth.REQUIRED_ENV`,
   `auth.CONFIG_TABLE` and `auth.CONFIG_REQUIRED` are.
2. Declare the `Setting` in `SETTINGS` in `src/reportal/settings.py`:

   ```python
   Setting(
       name="auth.required",
       describe="put every /api route behind an Authorization bearer token",
       kind=KIND_FLAG,
       read=auth.required,
       env=auth.REQUIRED_ENV,
       table=auth.CONFIG_TABLE,
       key=auth.CONFIG_REQUIRED,
       default="off",
   ),
   ```

   `name` carries exactly one dot, `describe` and `default` are non-empty, `read` is callable, and
   either `env` or `table` is set. With a `table`, `key` is required. `tests/test_settings.py`
   checks all of that.
3. Pick the `kind`: `KIND_TEXT`, `KIND_FLAG`, `KIND_LIST`, `KIND_PATH` or `KIND_SECRET`. A secret is
   never printed: the report carries whether one resolves and its length. A secret that belongs in
   the environment or the secret store, not in `reportal.toml`, also gets an entry in
   `SECRET_STORE_NAMES` so `problems` warns when it is committed to the file.
4. Keep one spelling per boolean. A flag reader must accept the same truthy set as
   `settings.FLAG_TRUTHY` and the same falsey set as `settings.FLAG_FALSEY`. A falsey
   environment value forces the flag off over the workspace file. The job pool is the
   exception that also treats any non-empty unrecognized value as present
   (`env_presence_wins`; `REPORTAL_JOBS_POOL` is the one case).
5. Write the reader so a wrong type or an unparsable value falls back to the default rather than
   raising, as `profiles.current` does, and so `settings.problems` can report the key.
6. Regenerate the catalog: `.venv/bin/python scripts/gen_docs.py` rewrites `docs/CONFIG.md` from
   `reportal.settings`. Do not hand-edit that file.

## Verify

1. `.venv/bin/python -m pytest tests/test_settings.py -q` proves every setting names a reader and a
   place it comes from, that names and `(table, key)` pairs are unique, and that the report resolves
   each setting's own value.
2. `.venv/bin/python -m pytest tests/test_generated_docs.py -q` proves `docs/CONFIG.md` matches a
   fresh regeneration.
3. `.venv/bin/reportal config --json` prints the setting with its value and its origin
   (`environment`, `workspace`, `secret store` or `default`), and `.venv/bin/reportal config`
   prints the same on the operator table.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#configuration)
- [CONFIG.md](../CONFIG.md)

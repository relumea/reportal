# Configuration

Sources: src/reportal/settings.py, src/reportal/_paths.py, src/reportal/profiles.py, src/reportal/secret_store.py

This subsystem owns where configuration comes from and how a workspace is found. Resolution is
first match wins: the environment, then the workspace `reportal.toml`, then the local secret store
for a credential only, then a default. A workspace is any ancestor directory holding the marker
`reportal.toml`, and no ancestor means `WorkspaceNotFound` rather than a fallback directory.

## Vocabulary

- `_paths.MARKER` (`reportal.toml`), `DB_ENV` (`REPORTAL_DB`), `CONFIG_TABLE` (`portal`) and
  `CONFIG_DB` (`db`); `reports_dir(binary_id)` and `binaries_dir()` are workspace subdirectories,
  and `stored_binary_path` says whether a path is reportal's own copy to remove.
- `WORKSPACE_DIRS` (`binaries`, `reports`, `symbols`), `SYMBOLS_DIR` and
  `ensure_workspace_dirs(root)`: the folders reportal owns inside a workspace.
- `settings.Setting`: one setting's `name`, `env`, `table`, `key`, `default`, `kind` (`text`,
  `flag`, `list`, `path`, `secret`) and the `read` accessor that resolves it; `SETTINGS`, `BY_NAME`
  and `BY_TABLE_KEY` index the surface, and `FLAG_TRUTHY` / `FLAG_FALSEY` are the
  on/off spelling sets a flag env accepts.
- `settings.report()` carries `settings`, `problems` and `count`; `problems` reports unknown
  tables/keys, wrong types, saas/auth conflicts, bad http(s) URLs, a missing FLIRT dir, and
  Stripe/VirusTotal without a secret; `failing()` means the file is unread.
- `profiles.PROFILE_ENV` (`REPORTAL_PROFILE`), `PROFILE_PERSONAL` and `PROFILE_SAAS`: the profile
  flips which guards run and never changes the tables or the routes.
- `secret_store`: table `secrets`, `SCOPE_LOCAL`/`SCOPE_TEAM`, `NO_TEAM` (0), `NAME_PATTERN`,
  `MAX_VALUE_BYTES`, `value_of`/`resolve_from_workspace` (the only value-returning reads), and the
  `InvalidSecretError`/`UnknownSecretError`/`ForbiddenSecretError` vocabulary.

## Wiring

`reportal init` writes the marker, the database and `ensure_workspace_dirs(root)` (the workspace's
own `docs/` is never created: an empty one would shadow the shipped manual); `reportal config`
prints `instance.describe()` plus `settings.report()` and exits 1 when `settings.failing()` is
non-empty. `serve` and `mcp` refuse to run on the same failing list. CLI: `secrets-set`,
`secrets-rm`, `secrets-list`. Readers: `auth`, `llm`, `external`, `sandbox`, `jobs`, `billing`,
`graph_backends`, `pipeline`, `remote_ingest` and `docs`.

## Invariants

- `database_path` resolves a relative `[portal] db` against the workspace root; `REPORTAL_DB` wins
  outright (`tests/test_paths.py`).
- Every value-returning secret read reports name, scope, team, byte length and hint only; the
  value leaves through `value_of` alone (`tests/test_secret_store.py`).
- `REPORTAL_PROFILE` then `[deployment] profile` decides the profile; anything else is `personal`
  (`tests/test_profiles.py`).
- Every setting's `read` agrees with the module's own predicate, and origin matches the reader
  (`tests/test_settings.py`). Under saas, `auth.required` origin follows the profile; a
  conflicting `REPORTAL_AUTH=off` is a problem, not a silent override.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#configuration)
- [CONFIG.md](../CONFIG.md)
